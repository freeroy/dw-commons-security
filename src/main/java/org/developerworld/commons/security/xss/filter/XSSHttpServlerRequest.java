package org.developerworld.commons.security.xss.filter;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.developerworld.commons.security.xss.XSSEscapeUtils;
import org.developerworld.commons.security.xss.XSSRequestEscapeHolder;

/**
 * 防XSS攻击请求对象
 * 
 * @author Roy Huang
 *
 */
public class XSSHttpServlerRequest extends HttpServletRequestWrapper {

	private HttpServletRequest request;

	public XSSHttpServlerRequest(HttpServletRequest request) {
		super(request);
		if (request != null && request instanceof XSSHttpServlerRequest)
			this.request = ((XSSHttpServlerRequest) request).getNativeServletRequest();
		else
			this.request = request;
	}

	/**
	 * 获取原生request
	 * 
	 * @return
	 */
	public HttpServletRequest getNativeServletRequest() {
		return request;
	}

	@Override
	public String getParameter(String arg0) {
		String rst = getNativeServletRequest().getParameter(arg0);
		if (rst == null || !XSSRequestEscapeHolder.isEscape())
			return rst;
		return escape(rst);
	}

	@Override
	public Map getParameterMap() {
		Map rm = getNativeServletRequest().getParameterMap();
		if (rm == null || !XSSRequestEscapeHolder.isEscape())
			return rm;
		Map rst = new LinkedHashMap(rm);
		Iterator<Entry> iterator = rm.entrySet().iterator();
		while (iterator.hasNext()) {
			Entry entry = iterator.next();
			Object data = entry.getValue();
			if (data == null)
				rst.put(entry.getKey(), data);
			else if (data instanceof String)
				rst.put(entry.getKey(), escape((String) entry.getValue()));
			else if (data instanceof String[]) {
				String[] _datas = (String[]) data;
				String[] newDatas = new String[_datas.length];
				for (int i = 0; i < _datas.length; i++) {
					newDatas[i] = escape(_datas[i]);
				}
				rst.put(entry.getKey(), newDatas);
			}
		}
		return rst;
	}

	@Override
	public String[] getParameterValues(String arg0) {
		String[] pvs = getNativeServletRequest().getParameterValues(arg0);
		if (pvs == null || !XSSRequestEscapeHolder.isEscape())
			return pvs;
		String[] rst = new String[pvs.length];
		for (int i = 0; i < pvs.length; i++)
			rst[i] = escape(pvs[i]);
		return rst;
	}

	/**
	 * 转码 若后期认为编码量不足，可通过
	 * 
	 * @param str
	 * @return
	 */
	protected String escape(String str) {
		return XSSEscapeUtils.escape(str);
	}

}
