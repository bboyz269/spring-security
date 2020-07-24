/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.taglibs.authz;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.taglibs.authz.AbstractAuthorizeTagContextTests.ChildContextConfig;
import org.springframework.security.taglibs.authz.AbstractAuthorizeTagContextTests.RootContextConfig;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.ContextHierarchy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringRunner.class)
@WebAppConfiguration
@ContextHierarchy({
		@ContextConfiguration(classes = RootContextConfig.class),
		@ContextConfiguration(classes = ChildContextConfig.class)
})
public class AbstractAuthorizeTagContextTests {

	@Autowired
	private AbstractAuthorizeTag authorizeTag;

	@Autowired
	private SecurityContext securityContext;

	@Before
	public void setup() {
		SecurityContextHolder.setContext(securityContext);
	}

	@Test
	public void test() throws IOException {
		Assertions.assertThat(authorizeTag.authorizeUsingAccessExpression())
				.as("AbstractAuthorizeTag should be able to pick up `expressionHandler` bean from child context")
				.isTrue();
	}


	@Configuration
	public static class RootContextConfig {
		//		@Bean
		//		public SecurityExpressionHandler expressionHandler() {
		//			return new DefaultWebSecurityExpressionHandler();
		//		}
	}

	@Configuration
	public static class ChildContextConfig {

		// Should this bean is move to root context, the test will pass.
		@Bean
		public SecurityExpressionHandler expressionHandler() {
			return new DefaultWebSecurityExpressionHandler();
		}

		@Bean
		public AbstractAuthorizeTag authorizeTag(final WebApplicationContext wac) {

			AuthzTag tag = new AuthzTag(wac.getServletContext());
			tag.setAccess("hasRole('USER')");
			return tag;
		}

		@Bean
		public SecurityContext securityContext() {
			Principal principal = Mockito.mock(Principal.class);
			return new SecurityContextImpl(new TestingAuthenticationToken(principal, "password",
					"ROLE_USER"));
		}
	}

	private static class AuthzTag extends AbstractAuthorizeTag {

		private final ServletRequest servletRequest;

		private final ServletResponse servletResponse;

		private final ServletContext servletContext;

		private AuthzTag(ServletContext servletContext) {
			this.servletContext = servletContext;
			servletRequest = new MockHttpServletRequest();
			servletResponse = new MockHttpServletResponse();
		}

		@Override
		protected ServletRequest getRequest() {
			return servletRequest;
		}

		@Override
		protected ServletResponse getResponse() {
			return servletResponse;
		}

		@Override
		protected ServletContext getServletContext() {
			return servletContext;
		}
	}

}
