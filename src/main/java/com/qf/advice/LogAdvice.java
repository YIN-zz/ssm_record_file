package com.qf.advice;


import org.apache.log4j.Logger;
import org.aspectj.lang.JoinPoint;

import java.text.DateFormat;
import java.util.Date;

/**
 * 2019/6/2915:10
 */
public class LogAdvice{

    Logger logger = Logger.getLogger("user");

    public String getInfo(JoinPoint joinPoint){
        String className = joinPoint.getTarget().getClass().getName();
        String methodName = joinPoint.getSignature().getName();
        Date date = new Date(System.currentTimeMillis());

        String info = "---类名：" + className + "---方法名：" + methodName + "---时间：" + date;

        return info;
    }

    public void before(JoinPoint joinPoint){
        logger.warn("开始执行--------" + getInfo(joinPoint));
    }

    public void after(JoinPoint joinPoint){
        logger.warn("执行结束--------" + getInfo(joinPoint));
    }

    public void afterThrowing(JoinPoint joinPoint, Throwable throwable){

        String message = throwable.getMessage();


        logger.error("执行异常--->" + getInfo(joinPoint) + "---异常信息--->" + message);

    }

}
