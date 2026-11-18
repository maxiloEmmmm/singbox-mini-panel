package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const webApplyReadyTimeout = 5 * time.Second

// webConfigSnapshot 保存一次提交所需的配置和规则。
type webConfigSnapshot struct {
	// Config 是已校验并写盘的主配置。
	Config Config
	// ForceProxy 是同次提交的强制代理规则。
	ForceProxy string
	// ForceDirect 是同次提交的强制直连规则。
	ForceDirect string
}

// webApplyStatus 表示最新保存版本的数据面应用结果。
type webApplyStatus struct {
	// Revision 是进程内递增的保存版本。
	Revision uint64 `json:"revision"`
	// State 是 pending、applying、applied 或 failed。
	State string `json:"state"`
	// Error 说明应用失败的原因。
	Error string `json:"error,omitempty"`
	// SingBoxStatus 是查询应用状态时的数据面进程状态。
	SingBoxStatus string `json:"sing_box_status,omitempty"`
}

// webApplyJob 表示一次待应用的提交。
type webApplyJob struct {
	// Revision 用于区分已被替代的提交。
	Revision uint64
	// Desired 是这次应用的配置快照。
	Desired webConfigSnapshot
	// Restart 表示缓存变化也需要重启数据面。
	Restart bool
}

// webApplyQueue 保存每个 Web 实例的串行应用状态，由 WebServer.Mutex 保护。
type webApplyQueue struct {
	// Context 在 Web 实例停止时取消。
	Context context.Context
	// Cancel 取消等待和后续应用。
	Cancel context.CancelFunc
	// Pending 是尚未开始的最新配置。
	Pending *webApplyJob
	// Running 表示已有 goroutine 在消费队列。
	Running bool
	// Applied 是上次应用成功的配置，用于判断能否热切。
	Applied *webConfigSnapshot
	// Status 对应最新一次提交。
	Status webApplyStatus
}

// loadWebConfigSnapshot 读取主配置和规则。示例：配置文件 + 两份规则 -> 应用快照。
func (a *App) loadWebConfigSnapshot() (webConfigSnapshot, error) {
	cfg, err := a.LoadConfig()
	return webConfigSnapshot{
		Config: cfg, ForceProxy: readOptionalText(a.ForceProxyPath), ForceDirect: readOptionalText(a.ForceDirectPath),
	}, err
}

// handleApplyStatus 返回最新应用结果。示例：GET /api/apply -> {"state":"applied"}。
func (w *WebServer) handleApplyStatus(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	w.Mutex.Lock()
	status := w.Apply.Status
	w.Mutex.Unlock()
	status.SingBoxStatus = singBoxStatus()
	writeJSON(rw, http.StatusOK, status)
}

// queueCurrentConfig 将缓存变更排入队列。示例：导入节点 -> 重新生成出站。
func (w *WebServer) queueCurrentConfig() error {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()
	snapshot, err := w.App.loadWebConfigSnapshot()
	if err == nil {
		w.enqueueApply(snapshot, snapshot, true)
	}
	return err
}

// enqueueApply 在持锁时登记最新版本。示例：待应用 A、保存 B -> 队列只剩 B。
func (w *WebServer) enqueueApply(before, desired webConfigSnapshot, restart bool) {
	q := &w.Apply
	if q.Applied == nil {
		q.Applied = &before
	}
	restart = restart || q.Status.State == "failed" || (q.Pending != nil && q.Pending.Restart)
	revision := q.Status.Revision + 1
	q.Pending = &webApplyJob{Revision: revision, Desired: desired, Restart: restart}
	q.Status = webApplyStatus{Revision: revision, State: "pending"}
	if !q.Running {
		q.Running = true
		go w.applyLoop()
	}
}

// applyLoop 串行处理保存版本。示例：A 失败、B 已提交 -> 继续应用 B。
func (w *WebServer) applyLoop() {
	q := &w.Apply
	for {
		w.Mutex.Lock()
		job := q.Pending
		if job == nil || q.Context.Err() != nil {
			q.Running = false
			w.Mutex.Unlock()
			return
		}
		before := *q.Applied
		q.Pending = nil
		q.Status.State = "applying"
		w.Mutex.Unlock()

		err := w.applySavedConfig(q.Context, before, job)

		w.Mutex.Lock()
		if err == nil {
			q.Applied = &job.Desired
		} else if q.Pending != nil {
			q.Pending.Restart = true
		}
		if q.Status.Revision == job.Revision {
			q.Status.State = "applied"
			if err != nil {
				q.Status.State = "failed"
				q.Status.Error = err.Error()
			}
		}
		w.Mutex.Unlock()
	}
}

// applySavedConfig 准备并应用已保存的快照。示例：TUN 排除项变化 -> 检查后重启。
func (w *WebServer) applySavedConfig(ctx context.Context, before webConfigSnapshot, job *webApplyJob) error {
	a := w.App
	if ServiceEnabled(job.Desired.Config) {
		// 更新缓存可能等待网络，所以在配置锁之外执行，切换前再检查版本。
		if err := a.UpdateChangedSubscriptions(&before.Config, &job.Desired.Config); err != nil {
			return err
		}
		if err := a.updateGeoFiles(job.Desired.Config.Update, true); err != nil {
			return err
		}
	}
	a.RuntimeMutex.Lock()
	defer a.RuntimeMutex.Unlock()
	if !w.isCurrentApply(job.Revision) {
		return errors.New("应用已被更新的配置替代")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	after := job.Desired
	plan := BuildWebApplyPlan(before.Config, before.ForceProxy, before.ForceDirect, after.Config, after.ForceProxy, after.ForceDirect)
	if !plan.ServiceEnabled {
		return a.stop()
	}
	if plan.Restart || job.Restart || !clashAPIReady() {
		data, err := a.generateSingBoxConfigText(after)
		if err != nil {
			return err
		}
		candidate, err := a.checkWebConfig(ctx, data)
		if err != nil {
			return err
		}
		defer os.Remove(candidate)
		if !w.isCurrentApply(job.Revision) {
			return errors.New("应用已被更新的配置替代")
		}
		if err := a.switchCheckedConfig(ctx, candidate); err != nil {
			return err
		}
	}
	if err := a.SyncSelectorSwitches(plan.SelectorSwitches); err != nil {
		return err
	}
	if len(plan.SelectorSwitches) > 0 {
		if err := a.CloseClashConnections(); err != nil {
			a.Logger.Warn("保存后清理旧连接失败 err=%v", err)
		}
	}
	return nil
}

// isCurrentApply 判断候选是否仍是最新版本。示例：检查期间保存 B -> 跳过 A 的切换。
func (w *WebServer) isCurrentApply(revision uint64) bool {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()
	return w.Apply.Status.Revision == revision
}

// checkWebConfig 写出并验证候选 JSON。示例：check 失败 -> 删除候选文件。
func (a *App) checkWebConfig(ctx context.Context, data string) (string, error) {
	dir := filepath.Dir(a.SingBoxConfig)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(dir, ".sboxctl-check-*.json")
	if err != nil {
		return "", err
	}
	validated := false
	defer func() {
		if !validated {
			_ = os.Remove(file.Name())
		}
	}()
	if _, err := file.WriteString(data); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Chmod(0644); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	binary, workDir := ResolveSingBoxRuntime()
	checkCtx, cancel := context.WithTimeout(ctx, webApplyReadyTimeout)
	output, err := exec.CommandContext(checkCtx, binary, "check", "-c", file.Name(), "-D", workDir).CombinedOutput()
	checkErr := checkCtx.Err()
	cancel()
	if checkErr != nil {
		return "", fmt.Errorf("sing-box 配置检查: %w", checkErr)
	}
	if err != nil {
		return "", fmt.Errorf("sing-box 配置检查失败: %w %s", err, strings.TrimSpace(string(output)))
	}
	validated = true
	return file.Name(), nil
}

// switchCheckedConfig 切换到已检查的文件。示例：新进程未就绪 -> 恢复旧数据面。
func (a *App) switchCheckedConfig(ctx context.Context, candidate string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	previous, readErr := os.ReadFile(a.SingBoxConfig)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	wasReady := clashAPIReady()
	if err := a.stopSingBoxProcess(); err != nil {
		return err
	}
	if err := os.Rename(candidate, a.SingBoxConfig); err != nil {
		if wasReady && ctx.Err() == nil {
			return errors.Join(err, a.startSingBoxProcess())
		}
		return err
	}
	a.Logger.Info("已切换 sing-box 配置 path=%s", a.SingBoxConfig)
	a.Logger.RotateFile(filepath.Join(a.Logger.Dir, "sing-box.log"))
	startErr := a.startSingBoxProcess()
	if startErr == nil {
		startErr = waitWebClashReady(ctx)
	}
	if startErr != nil && wasReady && readErr == nil {
		// 检查无法发现端口占用等运行时故障，保留旧数据面供后续修正。
		return errors.Join(startErr, a.restoreWebDataPlane(ctx, previous))
	}
	return startErr
}

// restoreWebDataPlane 恢复切换前的 JSON 和进程。示例：新进程未就绪 -> 启动旧配置。
func (a *App) restoreWebDataPlane(ctx context.Context, previous []byte) error {
	if err := a.stopSingBoxProcess(); err != nil {
		return fmt.Errorf("停止候选配置失败: %w", err)
	}
	if err := writeAtomicFile(a.SingBoxConfig, previous, 0644); err != nil {
		return fmt.Errorf("恢复旧配置失败: %w", err)
	}
	if ctx.Err() != nil {
		return nil
	}
	if err := a.startSingBoxProcess(); err != nil {
		return fmt.Errorf("启动旧配置失败: %w", err)
	}
	if err := waitWebClashReady(ctx); err != nil {
		return fmt.Errorf("旧配置未就绪: %w", err)
	}
	return nil
}

// waitWebClashReady 限时等待 Clash API。示例：进程反复退出 -> 返回超时。
func waitWebClashReady(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, webApplyReadyTimeout)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if clashAPIReady() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("等待 sing-box Clash API 就绪: %w", ctx.Err())
		case <-tick.C:
		}
	}
}
