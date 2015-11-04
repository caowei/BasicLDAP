package com.caowei.learn.ldap;

import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Note this class is not thread safe, please don't share instance between threads.
 * 
 * @author Cao Wei
 *
 */
public class LDAPClient {

	
	public final static String LDAP_NON_SSL_URL_PATTERN = "ldap://%s:%s/";
	public final static String LDAP_SSL_URL_PATTERN     = "ldaps://%s:%s/";
	public final static String TDS_USER_BASE_DN         = "DC=SP,DC=EDU,DC=SG";
	private InitialLdapContext ldapContext = null;
	private String             ldapUrl     = null;
	
	public InitialLdapContext getLdapContext() {
		return ldapContext;
	}

	public LDAPClient(String host, String port, boolean isSSL,
			String adminName, String adminPwd) throws NamingException{
				
		if (isSSL){
			this.ldapUrl = String.format(LDAP_SSL_URL_PATTERN, host,port);
		} else {
			this.ldapUrl = String.format(LDAP_NON_SSL_URL_PATTERN, host,port);
		}
		
		Hashtable<String,String> env = new Hashtable<String,String>();
		
		env.put(Context.INITIAL_CONTEXT_FACTORY,  "com.sun.jndi.ldap.LdapCtxFactory");
		env.put("com.sun.jndi.ldap.connect.pool", "true");
		env.put(Context.PROVIDER_URL, ldapUrl);
		env.put("com.sun.jndi.ldap.connect.timeout", "10000");
		env.put(Context.SECURITY_PRINCIPAL, adminName );
		env.put(Context.SECURITY_CREDENTIALS, adminPwd);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		//env.put(Context.REFERRAL, "follow");
		
		this.ldapContext = new InitialLdapContext (env, null);	
	}
	
	/**
	 * 
	 * @param containerDN
	 * @param userId
	 * @param attributes
	 * @throws NamingException
	 */
	public void createUser(String containerDN,String userId,Map<String,Object> attributes) throws NamingException{

			BasicAttributes ldapAttrs = retrieveAttributes(attributes);
			
			LdapName dn=new LdapName(containerDN);
			dn.add(new Rdn("principalName", userId));

			Attribute objectCls = new BasicAttribute("objectClass");
			objectCls.add("cimManagedElement");
			objectCls.add("eUser");
			objectCls.add("secUser");
			objectCls.add("top");
			
			ldapAttrs.put(objectCls);
			
			//getLdapContext().modifyAttributes(dn, DirContext.REPLACE_ATTRIBUTE, ldapAttrs);
			getLdapContext().createSubcontext(dn, ldapAttrs);
			
			System.out.println("Successfully create LDAP user " + dn);
		
	}
	
	/**
	 * Remove User
	 * @param userDN
	 * @throws NamingException
	 */
	public void removeUser(String userDN) throws NamingException{
		getLdapContext().destroySubcontext(userDN);
		
		System.out.println("LDAP Removed user " + userDN);
	}
	
	/**
	 * Search user DN
	 * 
	 * @param userCN
	 * @param baseContext
	 * @return
	 * @throws NamingException
	 */
	public String getUserDN(String baseContext,String userCN) throws NamingException{
		
		String userDN = "";
		
		String[] params = {userCN};
		SearchControls sc=new SearchControls();
		sc.setReturningAttributes(new String[0]);		  
		sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

		NamingEnumeration<SearchResult> result=null;
		try{
			result = getLdapContext().search(baseContext, "(cn={0})", params,  sc);

			while(result.hasMoreElements()){
				SearchResult sr = result.nextElement();
				
				userDN = sr.getNameInNamespace();
				
			}
		}finally{
			result.close();
		}
		return userDN;
	}
	
	
	private BasicAttributes retrieveAttributes(Map<String,Object> attributes){
		Set<String> keys = attributes.keySet();
		BasicAttributes ldapAttrs = new BasicAttributes();
		
		for (String key:keys){
			ldapAttrs.put(key, attributes.get(key));
		}
		
		return ldapAttrs;
	}
	
	/*
	 * Invoke this method to release connection
	 */
	public void close(){
		try {
			if (this.ldapContext != null){
				this.ldapContext.close();
			}
		} catch (NamingException e) {
			e.printStackTrace();
		}
	}

	public String getLdapUrl() {
		return ldapUrl;
	}
	
}
