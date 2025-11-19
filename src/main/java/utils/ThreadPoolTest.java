package utils;

import java.util.concurrent.TimeUnit;

/**
 * 线程池管理器测试类
 * 用于验证ThreadPoolManager的功能
 */
public class ThreadPoolTest {
    
    public static void main(String[] args) {
        System.out.println("开始测试线程池管理器...");
        
        // 创建线程池管理器
        ThreadPoolManager manager = new ThreadPoolManager();
        
        // 创建线程池
        manager.createThreadPool(5, 10);
        System.out.println("线程池创建成功");
        
        // 提交一些测试任务
        for (int i = 0; i < 20; i++) {
            final int taskId = i;
            manager.submitTask(() -> {
                try {
                    System.out.println("执行任务 " + taskId);
                    Thread.sleep(100); // 模拟工作
                    System.out.println("任务 " + taskId + " 完成");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        
        // 显示状态
        System.out.println("当前状态: " + manager.getStatus());
        
        // 等待任务完成
        try {
            Thread.sleep(3000);
            System.out.println("等待后的状态: " + manager.getStatus());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // 关闭线程池
        manager.shutdown();
        System.out.println("线程池已关闭");
        
        System.out.println("测试完成");
    }
} 