package utils;

import java.util.concurrent.Semaphore;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 速率限制器
 * 使用令牌桶算法控制请求频率
 */
public class RateLimiter {
    private final Semaphore semaphore;
    private final int maxRequestsPerSecond;
    private final ScheduledExecutorService scheduler;
    private final AtomicInteger currentRequests;
    private volatile boolean enabled;
    
    public RateLimiter(int maxRequestsPerSecond) {
        this.maxRequestsPerSecond = maxRequestsPerSecond;
        this.semaphore = new Semaphore(maxRequestsPerSecond);
        this.scheduler = Executors.newScheduledThreadPool(1);
        this.currentRequests = new AtomicInteger(0);
        this.enabled = true;
        
        // 每秒释放令牌
        scheduler.scheduleAtFixedRate(this::refillTokens, 1, 1, TimeUnit.SECONDS);
    }
    
    /**
     * 获取执行许可
     * @return 是否获取成功
     */
    public boolean tryAcquire() {
        if (!enabled) {
            return true; // 如果禁用限流，直接允许
        }
        
        boolean acquired = semaphore.tryAcquire();
        if (acquired) {
            currentRequests.incrementAndGet();
        }
        return acquired;
    }
    
    /**
     * 阻塞式获取执行许可
     * @throws InterruptedException 中断异常
     */
    public void acquire() throws InterruptedException {
        if (!enabled) {
            return; // 如果禁用限流，直接返回
        }
        
        semaphore.acquire();
        currentRequests.incrementAndGet();
    }
    
    /**
     * 阻塞式获取执行许可，带超时
     * @param timeout 超时时间
     * @param unit 时间单位
     * @return 是否在超时前获取成功
     * @throws InterruptedException 中断异常
     */
    public boolean tryAcquire(long timeout, TimeUnit unit) throws InterruptedException {
        if (!enabled) {
            return true; // 如果禁用限流，直接允许
        }
        
        boolean acquired = semaphore.tryAcquire(timeout, unit);
        if (acquired) {
            currentRequests.incrementAndGet();
        }
        return acquired;
    }
    
    /**
     * 释放许可（通常在请求完成后调用）
     */
    public void release() {
        if (!enabled) {
            return;
        }
        
        // 注意：不需要手动释放semaphore，因为我们使用定时补充的方式
        currentRequests.decrementAndGet();
    }
    
    /**
     * 每秒补充令牌
     */
    private void refillTokens() {
        // 将信号量重置为最大值
        int availablePermits = semaphore.availablePermits();
        int tokensToAdd = maxRequestsPerSecond - availablePermits;
        if (tokensToAdd > 0) {
            semaphore.release(tokensToAdd);
        }
        
        // 重置当前请求计数
        currentRequests.set(0);
    }
    
    /**
     * 启用限流
     */
    public void enable() {
        this.enabled = true;
    }
    
    /**
     * 禁用限流
     */
    public void disable() {
        this.enabled = false;
    }
    
    /**
     * 检查限流是否启用
     */
    public boolean isEnabled() {
        return enabled;
    }
    
    /**
     * 获取当前可用许可数
     */
    public int getAvailablePermits() {
        return semaphore.availablePermits();
    }
    
    /**
     * 获取当前秒内已发送的请求数
     */
    public int getCurrentRequests() {
        return currentRequests.get();
    }
    
    /**
     * 获取最大请求数限制
     */
    public int getMaxRequestsPerSecond() {
        return maxRequestsPerSecond;
    }
    
    /**
     * 获取状态信息
     */
    public String getStatus() {
        return String.format(
            "限流状态: %s, 最大请求/秒: %d, 当前可用: %d, 本秒已用: %d",
            enabled ? "启用" : "禁用",
            maxRequestsPerSecond,
            getAvailablePermits(),
            getCurrentRequests()
        );
    }
    
    /**
     * 关闭速率限制器
     */
    public void shutdown() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
} 