package org.developerworld.commons.security.xss.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.developerworld.commons.security.xss.XSSRequestEscapeHolder;
import org.developerworld.commons.servlet.AbstractUrlFilter;

/**
 * 跨站点脚本攻击过滤器
 * 
 * @author Roy Huang
 *
 */
public class XSSRequestFilter extends AbstractUrlFilter {

	@Override
	public void doFilterWhenUrlPass(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		try {
			XSSRequestEscapeHolder.setEscape(true);
			filterChain.doFilter(new XSSHttpServlerRequest((HttpServletRequest) request), response);
		} finally {
			XSSRequestEscapeHolder.clean();
		}
	}

}
