package org.developerworld.commons.security.xss;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.developerworld.commons.lang.MapBuilder;

public class XSSEscapeUtils {

	private static LinkedHashMap<String, String> escapeConvers;
	private static LinkedHashMap<String, String> unescapeConvers;
	static{
		//转码配置
		escapeConvers=(LinkedHashMap<String, String>) new MapBuilder<String, String>(new LinkedHashMap<String, String>())
			.put("&", "&amp;")
			.put("<", "&lt;")
			.put(">", "&gt;")
			.put("'", "&#039;")
			.put("\"", "&quot;")
			.map();
		//反向获取还原编码配置
		unescapeConvers=new LinkedHashMap<String,String>();
		List<String> keys=new ArrayList<String>(escapeConvers.keySet());
		for(int i=keys.size()-1;i>=0;i--)
			unescapeConvers.put(escapeConvers.get(keys.get(i)),keys.get(i));
	}

	public static String unescape(String str) {
		if (str==null)
			return str;
		for(String key:unescapeConvers.keySet())
			str=str.replaceAll(key,unescapeConvers.get(key));
		return str;
	}

	public static String escape(String str) {
		if (str==null)
			return str;
		for(String key:escapeConvers.keySet())
			str=str.replaceAll(key,escapeConvers.get(key));
		return str;
	}
	
	public final static void main(String args[]){
		String str="<a href=\"abc\" class='adfa'>&啊打发</a>";
		System.out.println(str);
		System.out.println(escape(str));
		System.out.println(unescape(escape(str)));
	}

}
