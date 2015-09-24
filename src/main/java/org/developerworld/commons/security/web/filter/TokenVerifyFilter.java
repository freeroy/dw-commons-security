package org.developerworld.commons.security.web.filter;

import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.developerworld.commons.servlet.AbstractUrlFilter;

/**
 * 令牌校验过滤器
 * 
 * @author Roy Huang
 * @version 20150729
 * 
 */
public class TokenVerifyFilter extends AbstractUrlFilter {

	private String unVerifyRedirect;// 不通过校验重定向位置
	private String unVerifyAjaxCallback;// 不通过校验输出的ajax返回
	private int maxTokenSize = 100;// 最大寄存token数目
	private boolean unBuildTokenOnAjaxGet = true;// 针对ajax get请求是否不生成token
	private String tokenRequestParameterName = "token";// 请求参数中的token参数名
	private String tokenAttributeName = TokenVerifyFilter.class.getName()
			+ "_tokens";// 寄存token的变量key

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		super.init(filterConfig);
		if (StringUtils.isNotBlank(filterConfig
				.getInitParameter("unVerifyRedirect")))
			unVerifyRedirect = filterConfig
					.getInitParameter("unVerifyRedirect");
		if (StringUtils.isNotBlank(filterConfig
				.getInitParameter("unVerifyAjaxCallback")))
			unVerifyAjaxCallback = filterConfig
					.getInitParameter("unVerifyAjaxCallback");
		if (StringUtils.isNotBlank(filterConfig
				.getInitParameter("tokenAttributeName")))
			tokenAttributeName = filterConfig
					.getInitParameter("tokenAttributeName");
		if (StringUtils.isNotBlank(filterConfig
				.getInitParameter("tokenRequestParameterName")))
			tokenRequestParameterName = filterConfig
					.getInitParameter("tokenRequestParameterName");
		if (StringUtils.isNotBlank(filterConfig
				.getInitParameter("unBuildTokenOnAjaxGet")))
			unBuildTokenOnAjaxGet = Boolean.valueOf(filterConfig
					.getInitParameter("unBuildTokenOnAjaxGet"));
		if (StringUtils.isNotBlank(filterConfig
				.getInitParameter("maxTokenSize")))
			maxTokenSize = Integer.valueOf(filterConfig
					.getInitParameter("maxTokenSize"));
	}

	public void doFilterWhenUrlPass(ServletRequest arg0, ServletResponse arg1,
			FilterChain arg2) throws IOException, ServletException {
		boolean isPass = true;
		HttpServletRequest request = (HttpServletRequest) arg0;
		if (request.getMethod() != null) {
			// 若是get请求，执行token构建逻辑
			if (request.getMethod().equalsIgnoreCase("get"))
				doBuildToken(request);
			// 若是post请求，执行token校验逻辑
			else if (request.getMethod().equalsIgnoreCase("post"))
				isPass = doVerifyToken(request);
			resetTokens(request);
		}
		// 若通过校验，则放行
		if (isPass)
			arg2.doFilter(arg0, arg1);
		// 不通过校验
		else {
			HttpServletResponse response = (HttpServletResponse) arg1;
			// 判断是否ajax请求,是旧输出固定json格式字符串
			String requestType = request.getHeader("X-Requested-With");
			if (StringUtils.isNotBlank(requestType)
					&& requestType.equalsIgnoreCase("XMLHttpRequest")) {
				// ajax请求
				String callback = unVerifyAjaxCallback == null ? ""
						: unVerifyAjaxCallback;
				response.getWriter().print(callback);
			}
			// 非ajax请求
			else {
				// 若配置了全局返回页，则跳转
				if (StringUtils.isNotBlank(unVerifyRedirect))
					response.sendRedirect(unVerifyRedirect);
				else {
					// 否则尝试跳至上一页
					String referer = request.getHeader("Referer");
					if (StringUtils.isNotBlank(referer))
						response.sendRedirect(referer);
					else
						response.getWriter()
								.print("<script language='javascript' type='text/javascript'>history.back()(</script>");
				}
			}
		}
	}

	/**
	 * 重置token
	 * 
	 * @param request
	 */
	protected void resetTokens(HttpServletRequest request) {
		Map<String, String> tokens = getTokens(request);
		if (tokens.size() > maxTokenSize) {
			Iterator<Entry<String, String>> _tokens = tokens.entrySet()
					.iterator();
			int removeCount = tokens.size() - maxTokenSize;
			while (_tokens.hasNext() && removeCount > 0) {
				_tokens.next();
				_tokens.remove();
				--removeCount;
			}
		}
	}

	/**
	 * 构建token
	 * 
	 * @param request
	 */
	private void doBuildToken(HttpServletRequest request) {
		if (unBuildTokenOnAjaxGet) {
			// ajax请求，不执行token构建
			String requestType = request.getHeader("X-Requested-With");
			if (StringUtils.isNotBlank(requestType)
					&& requestType.equalsIgnoreCase("XMLHttpRequest"))
				return;
		}
		// 构建token
		String token = buildToken(request);
		// 保存token
		saveToken(request, token);
	}

	/**
	 * 校验token
	 * 
	 * @param request
	 */
	private boolean doVerifyToken(HttpServletRequest request) {
		boolean rst = false;
		String reqToken = request.getParameter(tokenRequestParameterName);
		if (StringUtils.isNotBlank(reqToken)) {
			Map<String, String> tokens = getTokens(request);
			if (tokens != null) {
				String token = null;
				String referer = request.getHeader("Referer");
				if (StringUtils.isNotBlank(referer))
					token = tokens.get(referer);
				if (StringUtils.isBlank(token)) {
					Iterator<Entry<String, String>> _tokens = tokens.entrySet()
							.iterator();
					while (_tokens.hasNext()) {
						Entry<String, String> _token = _tokens.next();
						if (_token.getValue().equalsIgnoreCase(reqToken)) {
							token = _token.getValue();
							break;
						}
					}
				}
				rst = StringUtils.isNotBlank(token)
						&& token.equalsIgnoreCase(reqToken);
			}
		}
		return rst;
	}

	/**
	 * 构建token字符串(可供子类重构)
	 * 
	 * @param request
	 * @return
	 */
	protected String buildToken(HttpServletRequest request) {
		return UUID.randomUUID().toString();
	}

	/**
	 * 保存token(可供子类重构)
	 * 
	 * @param request
	 * @param token
	 */
	protected void saveToken(HttpServletRequest request, String token) {
		// token的寄存为集合，主要考虑多浏览器操作及单页面多次get请求情况，以免造成token失效
		Map<String, String> tokens = getTokens(request);
		if (tokens == null)
			tokens = new LinkedHashMap<String, String>();
		String url = request.getServletPath();
		if (StringUtils.isNotBlank(request.getQueryString()))
			url += "?" + request.getQueryString();
		tokens.put(url, token);
		saveTokens(request, tokens);
	}

	/**
	 * 保存整个tokens（可供子类重构）
	 * 
	 * @param session
	 * @param tokens
	 */
	protected void saveTokens(HttpServletRequest request,
			Map<String, String> tokens) {
		request.getSession(true).setAttribute(tokenAttributeName, tokens);
	}

	/**
	 * 获取token集合（可供子类重构）
	 * 
	 * @param request
	 * @return
	 */
	protected LinkedHashMap<String, String> getTokens(HttpServletRequest request) {
		HttpSession session = request.getSession(true);
		return (LinkedHashMap<String, String>) session
				.getAttribute(tokenAttributeName);
	}

	/**
	 * 删除token（可供子类重构）
	 * 
	 * @param request
	 * @param token
	 */
	protected void removeToken(HttpServletRequest request, String token) {
		Map<String, String> tokens = getTokens(request);
		if (tokens == null)
			return;
		// 若无指定删除token名， 则清空整个token寄存
		if (StringUtils.isBlank(token))
			tokens.clear();
		else {
			// 枸橘前导访问页，获取token信息
			String referer = request.getHeader("Referer");
			if (StringUtils.isNotBlank(referer)) {
				String _token = tokens.get(referer);
				// 若能找到，直接删除
				if (_token.equalsIgnoreCase(token)) {
					tokens.remove(referer);
					saveTokens(request, tokens);
					return;
				}
			}
			// 无法根据前导访问页删除token，则只能迭代查找执行删除
			Iterator<Entry<String, String>> _tokens = tokens.entrySet()
					.iterator();
			while (_tokens.hasNext()) {
				Entry<String, String> _token = _tokens.next();
				if (_token.getValue().equalsIgnoreCase(token)) {
					_tokens.remove();
					break;
				}
			}
		}
		saveTokens(request, tokens);
	}

}
