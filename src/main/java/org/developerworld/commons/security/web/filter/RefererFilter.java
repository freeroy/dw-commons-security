package org.developerworld.commons.security.web.filter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.developerworld.commons.lang.StringUtils;
import org.developerworld.commons.lang.StringWebUtils;
import org.developerworld.commons.servlet.AbstractUrlFilter;

/**
 * 来源过滤器
 * @author Roy Huang
 * @version 20120902
 *
 */
public class RefererFilter extends AbstractUrlFilter {

	public final static String INIT_PARAMETER_NAME_METHOD = "methods";
	public final static String INIT_PARAMETER_NAME_REFERERS = "referers";
	public final static String INIT_PARAMETER_NAME_REDIRECT="redirect";

	private Set<String> methods = new HashSet<String>();
	private Set<String> referers = new HashSet<String>();
	private String redirect;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		super.init(filterConfig);
		// 获取配置信息
		String methodStr = filterConfig
				.getInitParameter(INIT_PARAMETER_NAME_METHOD);
		if (StringUtils.isNotBlank(methodStr)) {
			String[] _methods = methodStr.split(",");
			for (String _method : _methods) {
				if (StringUtils.isNotBlank(_method))
					methods.add(_method.toLowerCase());
			}
		}
		String _refererStr = filterConfig
				.getInitParameter(INIT_PARAMETER_NAME_REFERERS);
		if (StringUtils.isNotBlank(_refererStr)) {
			String[] _referers = _refererStr.split(",");
			for (String _referer : _referers) {
				if (StringUtils.isNotBlank(_referer))
					referers.add(_referer.toLowerCase());
			}
		}
		redirect=filterConfig.getInitParameter(INIT_PARAMETER_NAME_REDIRECT);
	}

	@Override
	public void doFilterWhenUrlPass(ServletRequest arg0, ServletResponse arg1,
			FilterChain arg2) throws IOException, ServletException {
		boolean pass=true;
		String method=null;
		String referer=null;
		String servletPath=null;
		try{
			if(arg0 instanceof HttpServletRequest){
				HttpServletRequest request=(HttpServletRequest)arg0;
				method=request.getMethod();
				servletPath=request.getServletPath();
				//判断是否需要响应判断的method
				if(methods.size()==0 || methods.contains(method.toLowerCase())){
					String domain=request.getServerName();
					referer=request.getHeader("Referer");
					String refererDomain=null;
					if(StringUtils.isNotBlank(referer))
						refererDomain=StringWebUtils.getUrlDomain(referer);
					//若不是当前来源才判断
					if(!domain.equals(refererDomain)){
						//看是否允许的来源
						referer=referer==null?"":referer;
						pass=false;
						for(String _referer:referers){
							if(StringUtils.wildcardCapture(_referer,referer)){
								pass=true;
								break;
							}
						}
					}
				}
			}
		}
		finally{
			if(pass)
				arg2.doFilter(arg0, arg1);
			else if(StringUtils.isNotBlank(redirect) && arg1 instanceof HttpServletResponse)
				((HttpServletResponse)arg1).sendRedirect(redirect);
			else
				throw new ServletException("unsuport request for referer:"+referer+" and method:"+method+" to access:"+servletPath+"!");
		}			
	}
}
