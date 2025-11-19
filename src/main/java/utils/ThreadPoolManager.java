package utils;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 优化的线程池管理器
 * 提供线程池的创建、管理和监控功能
 */
public class ThreadPoolManager {
    
    private ExecutorService threadPool;
    private final AtomicInteger activeScans = new AtomicInteger(0);
    private final AtomicLong completedTasks = new AtomicLong(0);
    private final AtomicLong failedTasks = new AtomicLong(0);
    
    public ThreadPoolManager() {
    }
    
    /**
     * 创建优化的线程池
     * @param corePoolSize 核心线程数
     * @param maxPoolSize 最大线程数
     */
    public void createThreadPool(int corePoolSize, int maxPoolSize) {
        createThreadPool(corePoolSize, maxPoolSize, 60L, 100);
    }
    
    /**
     * 创建优化的线程池，提供更多配置参数
     * @param corePoolSize 核心线程数
     * @param maxPoolSize 最大线程数
     * @param keepAliveTime 空闲线程存活时间（秒）
     * @param queueCapacity 工作队列容量
     */
    public void createThreadPool(int corePoolSize, int maxPoolSize, long keepAliveTime, int queueCapacity) {
        if (threadPool != null && !threadPool.isShutdown()) {
            shutdown();
        }
        
        this.threadPool = new ThreadPoolExecutor(
            corePoolSize,                    // 核心线程数
            maxPoolSize,                     // 最大线程数
            keepAliveTime,                   // 空闲线程存活时间
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(queueCapacity),  // 工作队列，容量可配置
            new ThreadFactory() {
                private final AtomicInteger counter = new AtomicInteger(1);
                @Override
                public Thread newThread(Runnable r) {
                    Thread thread = new Thread(r, "scan-thread-" + counter.getAndIncrement());
                    thread.setDaemon(true);  // 设置为守护线程
                    return thread;
                }
            },
            new ThreadPoolExecutor.CallerRunsPolicy()  // 拒绝策略：调用者运行
        );
    }
    
    /**
     * 提交扫描任务
     * @param task 扫描任务
     */
    public void submitTask(Runnable task) {
        if (threadPool == null || threadPool.isShutdown()) {
            throw new IllegalStateException("线程池未初始化或已关闭");
        }
        
        activeScans.incrementAndGet();
        threadPool.submit(() -> {
            try {
                task.run();
                completedTasks.incrementAndGet();
            } catch (Exception e) {
                failedTasks.incrementAndGet();
                // 记录错误日志
                System.err.println("扫描任务执行失败: " + e.getMessage());
                e.printStackTrace();
            } finally {
                // 活跃任务计数减一
                activeScans.decrementAndGet();
            }
        });
    }
    
    /**
     * 等待所有任务完成
     * @param timeout 超时时间
     * @param unit 时间单位
     * @return 是否在超时前完成
     */
    public boolean waitForCompletion(long timeout, TimeUnit unit) {
        if (threadPool == null) {
            return true;
        }
        
        try {
            return threadPool.awaitTermination(timeout, unit);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
    
    /**
     * 关闭速率限制器
     */
    public void shutdown() {
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdown();
            try {
                // 等待60秒让任务完成
                if (!threadPool.awaitTermination(60, TimeUnit.SECONDS)) {
                    // 如果超时，强制关闭
                    threadPool.shutdownNow();
                    // 再等待60秒
                    if (!threadPool.awaitTermination(60, TimeUnit.SECONDS)) {
                        System.err.println("线程池无法完全关闭");
                    }
                }
            } catch (InterruptedException e) {
                // 如果被中断，强制关闭
                threadPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
    
    /**
     * 强制关闭线程池
     */
    public void shutdownNow() {
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdownNow();
        }
    }
    

    
    /**
     * 检查线程池是否已关闭
     * @return 是否已关闭
     */
    public boolean isShutdown() {
        return threadPool == null || threadPool.isShutdown();
    }
    
    /**
     * 获取活跃扫描数
     * @return 活跃扫描数
     */
    public int getActiveScans() {
        return activeScans.get();
    }
    
    /**
     * 获取已完成任务数
     * @return 已完成任务数
     */
    public long getCompletedTasks() {
        return completedTasks.get();
    }
    
    /**
     * 获取失败任务数
     * @return 失败任务数
     */
    public long getFailedTasks() {
        return failedTasks.get();
    }
    
    /**
     * 获取线程池状态信息
     * @return 状态信息字符串
     */
    public String getStatus() {
        if (threadPool == null) {
            return "线程池未初始化";
        }
        
        StringBuilder status = new StringBuilder();
        
        if (threadPool instanceof ThreadPoolExecutor) {
            ThreadPoolExecutor executor = (ThreadPoolExecutor) threadPool;
            status.append(String.format(
                "活跃线程: %d, 核心线程: %d, 最大线程: %d, 队列大小: %d, 已完成: %d, 失败: %d",
                executor.getActiveCount(),
                executor.getCorePoolSize(),
                executor.getMaximumPoolSize(),
                executor.getQueue().size(),
                completedTasks.get(),
                failedTasks.get()
            ));
        } else {
            status.append("线程池运行中");
        }
        
        return status.toString();
    }
    
    /**
     * 重置统计信息
     */
    public void resetStats() {
        completedTasks.set(0);
        failedTasks.set(0);
    }
} 