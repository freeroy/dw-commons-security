package org.developerworld.commons.security.xss.tag;

import java.io.IOException;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.JspWriter;

import org.developerworld.commons.security.xss.XSSEscapeUtils;
import org.developerworld.commons.servlet.jsp.tagext.BodyTagSupport;

/**
 * XSS解码
 * @author Roy Huang
 *
 */
public class XSSUnescapeTag extends BodyTagSupport {

	private Object value;

	public void setValue(Object value) {
		this.value = value;
	}

	@Override
	public int doStartTag() throws JspException {
		super.doStartTag();
		try {
			if (value != null) {
				if (value instanceof String)
					getOut().print(XSSEscapeUtils.unescape((String) value));
				else
					getOut().print(value);
				return SKIP_BODY;
			}
			return EVAL_BODY_BUFFERED;
		} catch (IOException e) {
			throwJspException(e.getMessage(), e);
		}
		return SKIP_BODY;
	}

	@Override
	public int doAfterBody() throws JspException {
		String rst = getBodyString();
		if (rst != null) {
			rst = XSSEscapeUtils.unescape(rst);
			JspWriter out = bodyContent.getEnclosingWriter();
			try {
				out.print(rst);
			} catch (IOException e) {
				throwJspException(e.getMessage(), e);
			}
			bodyContent.clearBody();
		}
		super.doAfterBody();
		return SKIP_BODY;
	}
}
