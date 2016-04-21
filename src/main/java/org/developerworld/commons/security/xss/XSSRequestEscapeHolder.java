package org.developerworld.commons.security.xss;

/**
 * 编码上下文控制
 * @author Roy Huang
 *
 */
public class XSSRequestEscapeHolder {

	private final static ThreadLocal<Boolean> ESCAPE_REQUEST = new ThreadLocal<Boolean>();

	/**
	 * 获取编码状态
	 * @return
	 */
	public static boolean isEscape() {
		return ESCAPE_REQUEST.get() != null && ESCAPE_REQUEST.get();
	}
	
	/**
	 * 设置是否进行编码
	 * @param escape
	 */
	public static void setEscape(boolean escape){
		ESCAPE_REQUEST.set(escape);
	}
	
	/**
	 * 清除编码配置
	 */
	public static void clean(){
		ESCAPE_REQUEST.set(null);
		ESCAPE_REQUEST.remove();
	}

}
