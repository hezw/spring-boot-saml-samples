/*
 * Copyright 2016 Vincenzo De Notaris
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */

package com.vdenotaris.spring.boot.security.saml.web.config.saml;

import com.vdenotaris.spring.boot.security.saml.web.config.saml.SAMLConfigurationBean.SignatureAlgorithm;
import com.vdenotaris.spring.boot.security.saml.web.core.SAMLUserDetailsServiceImpl;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	private static final Logger LOG = LoggerFactory.getLogger(WebSecurityConfig.class);

	@Value("${app.env:boot-saml-sample}")
	private String appEnv;

    private final String metadataKey="rektec"; //证书别名
    private final String metadataPassword="p@ssw0rd"; //证书密码


    private ENVIRONMENT getEnvironment(){
        return ENVIRONMENT.getEnumByAppName(appEnv);
    }
    @Autowired
    private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

	public enum ENVIRONMENT {
		
		UAT("dcjavaspringsaml2sample", ".ops1.ca-east.mybluemix.net", "/metadata/idp_metadata/federationmetadata.xml"),  	// Hitting UAT from the dedicated
		PROD("prodssopoc",".ops1.ca-east.mybluemix.net", "/metadata/idp_metadata/federationmetadata.xml"), 					// Hitting Prod from the dedicated env
		PUBLIC_PROD("SSoPOC",".mybluemix.net", "/metadata/idp_metadata/prod_federationmetadata.xml"),						// Hitting Prod from Public env
//		PUBLIC_NEW_PROD("SSoPOC",".mybluemix.net", "/metadata/idp_metadata/new_federationmetadata.xml");					// Hitting new ADFS Prod from Public env
//		PUBLIC_NEW_PROD("adfs",".hcn.fun:40443", "/federationmetadata/2007-06/federationmetadata.xml");					// Hitting new ADFS Prod from Public env
		PUBLIC_NEW_TEST("boot-saml-sample",".herokuapp.com", "/federationmetadata/2007-06/federationmetadata.xml"),				// Hitting new ADFS Prod from Public env
		PUBLIC_NEW_PROD("javaapp",".hcn.fun:41443", "/federationmetadata/2007-06/federationmetadata.xml");					// Hitting new ADFS Prod from Public env

		private final String applicationName;
		private final String applicationPrefix;
		private final String metadataPath;
		private ENVIRONMENT(String appName, String appPrefix, String pathToMetaData) {
			this.applicationName = appName;
			this.applicationPrefix = appPrefix;
			this.metadataPath = pathToMetaData;
		}
		String getAppName() {
			return this.applicationName;
		}
		String getAppPrefix() {
			return this.applicationPrefix;
		}
		public String getMetadataPath() {
			return metadataPath;
		}		
		String getFullAppName() {
			return (getAppName()+getAppPrefix());
		}
        public static ENVIRONMENT getEnumByAppName(String appName){
            for (ENVIRONMENT env: ENVIRONMENT.values()) {
                if(env.applicationName.equals(appName)){
                    return env;
                }
            }
            return null;
        }
	}

    // Initialization of the velocity engine
    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }
 
    // XML parser pool needed for OpenSAML parsing
    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }
 
    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }
 
    // Bindings, encoders and decoders used for creating and parsing messages
    @Bean
    public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }
 
    @Bean
    public HttpClient httpClient() {
    	return new HttpClient(multiThreadedHttpConnectionManager());
    }
 
    // SAML Authentication Provider responsible for validating of received SAML
    // messages
    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }
 
    // Provider of default SAML Context
    @Bean
    public SAMLContextProviderImpl contextProvider() {
    	SAMLContextProviderLB samlContextProviderLB  = new SAMLContextProviderLB();
    	samlContextProviderLB.setScheme("https");
        samlContextProviderLB.setServerName(getEnvironment().getFullAppName());
    	samlContextProviderLB.setServerPort(443);
    	samlContextProviderLB.setIncludeServerPortInRequestURL(false);
    	samlContextProviderLB.setContextPath("/");
    	return samlContextProviderLB;
    }
 
    // Initialization of OpenSAML library
    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
    	return new CustomSAMLBootstrap();
    }
 
    // Logger for SAML messages and events
    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }
 
    // SAML 2.0 WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }
 
    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }
 
    // SAML 2.0 Web SSO profile
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }
 
    // SAML 2.0 Holder-of-Key Web SSO profile
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }
 
    // SAML 2.0 ECP profile
    @Bean
    public WebSSOProfileECPImpl ecpprofile() {
        return new WebSSOProfileECPImpl();
    }
 
    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }
    
    // Central storage of cryptographic keys
    //TODO: 2022/9/8  key、password 是否有用
    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/samlKeystore.jks");
        String storePass = metadataPassword;
        String defaultKey = metadataKey;
        Map<String, String> passwords = new HashMap<>();
        passwords.put(defaultKey, storePass);
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }
 
    // Setup TLS Socket Factory
    @Bean
    public TLSProtocolConfigurer tlsProtocolConfigurer() {
    	return new TLSProtocolConfigurer();
    }
    
    @Bean
    public ProtocolSocketFactory socketFactory() {
        return new TLSProtocolSocketFactory(keyManager(), null, "default");
    }

    @Bean
    public Protocol socketFactoryProtocol() {
        return new Protocol("https", socketFactory(), 443);
    }

    @Bean
    public MethodInvokingFactoryBean socketFactoryInitialization() {
        MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
        methodInvokingFactoryBean.setTargetClass(Protocol.class);
        methodInvokingFactoryBean.setTargetMethod("registerProtocol");
        Object[] args = {"https", socketFactoryProtocol()};
        methodInvokingFactoryBean.setArguments(args);
        return methodInvokingFactoryBean;
    }
    
    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }
 
    // Entry point to initialize authentication, default values taken from
    // properties file
    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    //TODO: 2022/9/8  SigningKey、EncryptionKey 是否有用
    @Bean
    public ExtendedMetadata extendedSignedMetadata() {
    	ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    	extendedMetadata.setSignMetadata(false);
    	extendedMetadata.setSslHostnameVerification("allowAll");
    	extendedMetadata.setSigningAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    	extendedMetadata.setSigningKey(metadataKey);
    	extendedMetadata.setEncryptionKey(metadataKey);
    	extendedMetadata.setSecurityProfile("metaiop");
    	return extendedMetadata;
    }
    
    // Setup advanced info about metadata
    //TODO: 2022/9/8  SigningKey、EncryptionKey 是否有用
    @Bean
    public ExtendedMetadata extendedMetadata() {
    	ExtendedMetadata extendedMetadata = new ExtendedMetadata();
//    	extendedMetadata.setIdpDiscoveryEnabled(true); 
    	extendedMetadata.setSignMetadata(false);
    	extendedMetadata.setSigningAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    	extendedMetadata.setSigningKey(metadataKey);//ssocircle
    	extendedMetadata.setEncryptionKey(metadataKey);
    	extendedMetadata.setSecurityProfile("metaiop");
    	return extendedMetadata;
    }
    
    // IDP Discovery Service
    @Bean
    public SAMLDiscovery samlIDPDiscovery() {
        SAMLDiscovery idpDiscovery = new SAMLDiscovery();
        idpDiscovery.setIdpSelectionPath("/saml/idpSelection");
        return idpDiscovery;
    }

    //TODO: 2022/9/8  调试配置文件
	@Bean
	@Qualifier("idp-adfs")
	public ExtendedMetadataDelegate adfsExtendedMetadataProvider() throws MetadataProviderException {
		Timer backgroundTaskTimer = new Timer(true);
		ClasspathResource metadata = null;
        try {
        	metadata = new ClasspathResource(getEnvironment().getMetadataPath());
        } catch (Exception e) {
        	LOG.error("Couldn't load federationmetadata.xml.");
        }
		
		ResourceBackedMetadataProvider resourceBackedMetadataProvider = new ResourceBackedMetadataProvider(backgroundTaskTimer, metadata);
		resourceBackedMetadataProvider.setParserPool(parserPool());
		
		ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(resourceBackedMetadataProvider, extendedSignedMetadata());
		extendedMetadataDelegate.setMetadataTrustCheck(false);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		return extendedMetadataDelegate;
	}
	
    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do no forget to call iniitalize method on providers
    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
        providers.add(adfsExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }
 
    // Filter automatically generates default SP metadata
    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        StringBuilder theURL = new StringBuilder("https://");
        theURL.append(getEnvironment().getFullAppName());
        metadataGenerator.setEntityId(theURL.toString());
        metadataGenerator.setExtendedMetadata(extendedSignedMetadata());
        metadataGenerator.setEntityBaseURL(theURL.toString());
        metadataGenerator.setIncludeDiscoveryExtension(true);
        metadataGenerator.setKeyManager(keyManager()); 
        return metadataGenerator;
    }
 
    // The filter is waiting for connections on URL suffixed with filterSuffix
    // and presents SP metadata there
    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }
     
    // Handler deciding where to redirect user after successful login
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/landing");
        return successRedirectHandler;
    }
    
	// Handler deciding where to redirect user after failed login
    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
    	SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
    	failureHandler.setUseForward(true);
    	failureHandler.setDefaultFailureUrl("/error");
    	return failureHandler;
    }
     
    @Bean
    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOHoKProcessingFilter;
    }
    
    // Processing filter for WebSSO profile messages
    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOProcessingFilter;
    }
     
    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }
     
    // Handler for successful logout
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl("/");
        return successLogoutHandler;
    }
     
    // Logout handler terminating local session
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler =  new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }
 
    // Filter processing incoming logout messages
    // First argument determines URL user will be redirected to after successful
    // global logout
    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
    }
     
    // Overrides default logout processing filter with the one processing SAML
    // messages
    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(	successLogoutHandler(),
						                new LogoutHandler[] { logoutHandler() },
						                new LogoutHandler[] { logoutHandler() });
    }
	
    // Bindings
    private ArtifactResolutionProfile artifactResolutionProfile() {
        final ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient());
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
        return artifactResolutionProfile;
    }
    
    @Bean
    public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
    }
 
    @Bean
    public HTTPSOAP11Binding soapBinding() {
        return new HTTPSOAP11Binding(parserPool());
    }
    
    @Bean
    public HTTPPostBinding httpPostBinding() {
    	return new HTTPPostBinding(parserPool(), velocityEngine());
    }
    
    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
    	return new HTTPRedirectDeflateBinding(parserPool());
    }
    
    @Bean
    public HTTPSOAP11Binding httpSOAP11Binding() {
    	return new HTTPSOAP11Binding(parserPool());
    }
    
    @Bean
    public HTTPPAOS11Binding httpPAOS11Binding() {
    	return new HTTPPAOS11Binding(parserPool());
    }
    
    // Processor
	@Bean
	public SAMLProcessorImpl processor() {
		Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
		bindings.add(httpRedirectDeflateBinding());
		bindings.add(httpPostBinding());
		bindings.add(artifactBinding(parserPool(), velocityEngine()));
		bindings.add(httpSOAP11Binding());
		bindings.add(httpPAOS11Binding());
		return new SAMLProcessorImpl(bindings);
	}
    
	/**
	 * Define the security filter chain in order to support SSO Auth by using SAML 2.0
	 * 
	 * @return Filter chain proxy
	 * @throws Exception
	 */
    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"), metadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"), samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"), samlWebSSOHoKProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"), samlLogoutProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"), samlIDPDiscovery()));
        return new FilterChainProxy(chains);
    }
     
    /**
     * Returns the authentication manager currently used by Spring.
     * It represents a bean definition with the aim allow wiring from
     * other classes performing the Inversion of Control (IoC).
     * 
     * @throws  Exception 
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    
    @Bean(name = "SAMLConfigurationBean", initMethod="configureAlgorithm")
    public SAMLConfigurationBean SAMLConfigurationBean() {
    	SAMLConfigurationBean con = new SAMLConfigurationBean();
    	con.setSignatureAlgorithm(SignatureAlgorithm.SHA256);
    	return con;
    }
    
    /**
     * Defines the web based security configuration.
     * 
     * @param   http It allows configuring web based security for specific http requests.
     * @throws  Exception 
     */
    @Override  
    protected void configure(HttpSecurity http) throws Exception {
        
    	http.httpBasic().authenticationEntryPoint(samlEntryPoint());
        
        /*http.requiresChannel().anyRequest().requiresSecure();*/
        
        http.csrf().disable();
        
        http
            .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
            .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
        http        
            .authorizeRequests()
            .antMatchers("/").permitAll()
            .antMatchers("/error").permitAll()
            .antMatchers("/saml/**").permitAll()
            .antMatchers("/federationmetadata/**").permitAll()
            .anyRequest().authenticated();

        http.logout().logoutSuccessUrl("/");
    }


    /**
     * Sets a custom authentication provider.
     * 
     * @param   auth SecurityBuilder used to create an AuthenticationManager.
     * @throws  Exception 
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(samlAuthenticationProvider());
    }   
    
  /*  @Bean
    public TomcatEmbeddedServletContainerFactory tomcatEmbeddedServletContainerFactory(){
        return new TomcatEmbeddedServletContainerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
    }*/
    

}