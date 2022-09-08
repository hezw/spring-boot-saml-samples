Spring Boot-based sample Service Provider by using Spring Security SAML extension [![Build Status](https://travis-ci.org/vdenotaris/spring-boot-security-saml-sample.svg?branch=master)](https://travis-ci.org/vdenotaris/spring-boot-security-saml-sample) [![DOI](https://zenodo.org/badge/22013861.svg)](https://zenodo.org/badge/latestdoi/22013861)
====================

## References

#### Spring Boot

Spring Boot makes it easy to create Spring-powered, production-grade applications and services with absolute minimum fuss. It takes an opinionated view of the Spring platform so that new and existing users can quickly get to the bits they need.

- **Website:** [http://projects.spring.io/spring-boot/](http://projects.spring.io/spring-boot/)

#### Spring Security SAML Extension

Spring SAML Extension allows seamless inclusion of SAML 2.0 Service Provider capabilities in Spring applications. All products supporting SAML 2.0 in Identity Provider mode (e.g. ADFS 2.0, Shibboleth, OpenAM/OpenSSO, Ping Federate, Okta) can be used to connect with Spring SAML Extension.

- **Website:** [http://projects.spring.io/spring-security-saml/](http://projects.spring.io/spring-security-saml/)

---------

#### 一键部署

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://dashboard.heroku.com/apps/boot-saml-sample/deploy/github)

> 如果被heroku 提示错误，请用 github action 来部署。

> 部署成功后，可以先用浏览器访问 https://boot-saml-sample.herokuapp.com  ， 查看页面是否能正常访问。会显示一个随机的维基百科页面。

## Project description

Currently Spring Security SAML module doesn't provide a starter for Spring Boot. Moreover, its configuration is XML-based as of this writing. The aim of this project is to explain how to develop a **Service Provider (SP)** which uses **Spring Boot** (`1.4.0.RELEASE`) and **Spring Security SAML Extension** (`1.0.2.RELEASE`), by defining an annotation-based configuration (**Java Configuration**). **Thymeleaf** is also used as template engine.

**SSOCircle** ([ssocircle.com](http://www.ssocircle.com/en/portfolio/publicidp/)) is used as public Identity Provider for test purpose.

- **Author:** Vincenzo De Notaris ([dev@vdenotaris.com](mailto:dev@vdenotaris.com))
- **Website:** [vdenotaris.com](http://www.vdenotaris.com)
- **Version:**  ` 1.4.0.RELEASE `
- **Date**: 2016-09-09

Thanks to *Vladimír Schäfer* ([github.com/vschafer](https://github.com/vschafer)) for supporting my work.

#### Unit tests

I would like to say thank you to *Alexey Syrtsev* ([github.com/airleks](https://github.com/airleks)) for his contribution on unit tests.

| Metric | Result |
| ------------- | -----:|
| Coverage % | 99% |
| Lines Covered | 196 |
| Total Lines | 199 |

#### Useful notes

1. Sometimes SSO Circle could display you an error during the authenticaton process. In this case, please update your federation metadata directly on [https://idp.ssocircle.com](https://idp.ssocircle.com):

	> Manage Metadata > Service Provider Metadata
	
	Remove the current record and add a new one, using your FQDN and providing a new copy of your metadata: your can retrieve them at [http://localhost:8080/saml/metadata](http://localhost:8080/saml/metadata).

2. When the project version corresponds with the Spring Boot parent version, Maven may give you a warning as follows:

	> Version is duplicate of parent version.

	Actually there is nothing wrong with the used configuration, thus you can just ignore that message.

###License

    Copyright 2016 Vincenzo De Notaris

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	    http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.



