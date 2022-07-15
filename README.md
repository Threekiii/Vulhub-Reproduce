# Vulhub-Reproduce
**【免责声明】本仓库所涉及的技术、思路和工具仅供安全技术研究，任何人不得将其用于非授权渗透测试，不得将其用于非法用途和盈利，否则后果自行承担。**

Vulhub漏洞复现，不定时更新。感谢[@Vulhub](https://vulhub.org/)提供开源漏洞靶场。

## 0x01 项目导航

* Adobe ColdFusion 反序列化漏洞 CVE-2017-3066
* Adobe ColdFusion 文件读取漏洞 CVE-2010-2861
* Apache ActiveMQ 任意文件写入漏洞 CVE-2016-3088
* Apache ActiveMQ 反序列化漏洞 CVE-2015-5254
* Apache Airflow Celery 消息中间件命令执行 CVE-2020-11981
* Apache Airflow 示例DAG中的命令注入 CVE-2020-11978
* Apache Airflow 默认密钥导致的权限绕过 CVE-2020-17526
* Apache APISIX 默认密钥漏洞 CVE-2020-13945
* Apache Dubbo Java反序列化漏洞 CVE-2019-17564
* Apache Flink 小于1.9.1远程代码执行 CVE-2020-17518
* Apache Flink 目录遍历漏洞 CVE-2020-17519
* Apache HTTP Server 2.4.48 mod_proxy SSRF漏洞 CVE-2021-40438
* Apache HTTP Server 2.4.49 路径穿越漏洞 CVE-2021-41773
* Apache HTTP Server 2.4.50 路径穿越漏洞 CVE-2021-42013
* Apache HTTPd 多后缀解析漏洞
* Apache HTTPd 换行解析漏洞 CVE-2017-15715
* Apache Log4j Server 反序列化命令执行漏洞 CVE-2017-5645
* Apache Log4j2 lookup JNDI 注入漏洞 CVE-2021-44228
* Apache OfBiz 反序列化命令执行漏洞 CVE-2020-9496
* Apache Shiro 1.2.4 反序列化漏洞 CVE-2016-4437
* Apache Shiro 认证绕过漏洞 CVE-2020-1957
* Apache Skywalking 8.3.0 SQL注入漏洞
* Apache Solr RemoteStreaming 文件读取与SSRF漏洞
* Apache Solr Velocity 注入远程命令执行漏洞 CVE-2019-17558
* Apache Solr XML 实体注入漏洞 CVE-2017-12629
* Apache Solr 远程命令执行漏洞 CVE-2017-12629
* Apache Solr 远程命令执行漏洞 CVE-2019-0193
* Apache SSI 远程命令执行漏洞
* Apache Tomcat AJP 文件包含漏洞 CVE-2020-1938
* Apache Tomcat PUT方法任意写文件漏洞 CVE-2017-12615
* Apache Tomcat8 弱口令+后台getshell漏洞
* Apache Unomi 远程表达式代码执行漏洞 CVE-2020-13942
* Apereo CAS 4.1 反序列化命令执行漏洞
* AppWeb认证绕过漏洞 CVE-2018-8715
* Aria2 任意文件写入漏洞
* Atlassian Confluence OGNL表达式注入代码执行漏洞 CVE-2021-26084
* Atlassian Confluence 路径穿越与命令执行漏洞 CVE-2019-3396
* Celery 4.0 Redis未授权访问+Pickle反序列化利用
* Confluence OGNL表达式注入命令执行漏洞 CVE-2022-26134
* Couchdb 任意命令执行漏洞 CVE-2017-12636
* Couchdb 垂直权限绕过漏洞 CVE-2017-12635
* Discuz 7.x6.x 全局变量防御绕过导致代码执行
* Discuz!X ≤3.4 任意文件删除漏洞
* Django  2.0.8 任意URL跳转漏洞 CVE-2018-14574
* Django debug page XSS漏洞 CVE-2017-12794
* Django GIS SQL注入漏洞 CVE-2020-9402
* Django JSONField  HStoreField SQL注入漏洞 CVE-2019-14234
* Django QuerySet.order_by() SQL注入漏洞 CVE-2021-35042
* Django Trunc(kind) and Extract(lookup_name) SQL注入漏洞 CVE-2022-34265
* DNS域传送漏洞
* Docker daemon api 未授权访问漏洞
* Drupal  7.32 “Drupalgeddon” SQL注入漏洞 CVE-2014-3704
* Drupal Core 8 PECL YAML 反序列化任意代码执行漏洞 CVE-2017-6920
* Drupal Drupalgeddon 2 远程代码执行漏洞 CVE-2018-7600
* Drupal XSS漏洞 CVE-2019-6341
* Drupal 远程代码执行漏洞 CVE-2018-7602
* Drupal 远程代码执行漏洞 CVE-2019-6339
* ECShop 2.x3.x SQL注入任意代码执行漏洞
* ECShop 4.x collection_list SQL注入
* Fastjson 1.2.24 反序列化导致任意命令执行漏洞
* Fastjson 1.2.47 远程命令执行漏洞
* FFmpeg 任意文件读取漏洞SSRF漏洞 CVE-2016-1897+CVE-2016-1898
* Flask Jinja2 服务端模板注入漏洞
* Flask（Jinja2） 服务端模板注入漏洞
* GhostScript 沙箱绕过（命令执行）漏洞 CVE-2018-16509
* GhostScript 沙箱绕过（命令执行）漏洞 CVE-2018-19475
* GhostScript 沙箱绕过（命令执行）漏洞 CVE-2019-6116
* GIT-SHELL 沙盒绕过 CVE-2017-8386
* Gitea 1.4.0 目录穿越导致命令执行漏洞
* GitLab 任意文件读取漏洞 CVE-2016-9086
* GitLab 远程命令执行漏洞 CVE-2021-22205
* Gitlist 0.6.0 远程命令执行漏洞 CVE-2018-1000533
* GlassFish 任意文件读取漏洞
* GoAhead Server 环境变量注入 CVE-2021-42342
* GoAhead 远程命令执行漏洞 CVE-2017-17562
* Grafana管理后台SSRF
* H2 Database Console 未授权访问
* Hadoop YARN ResourceManager 未授权访问
* Imagemagick PDF密码位置命令注入漏洞 CVE-2020-29599
* Imagetragick 命令执行漏洞 CVE-2016–3714
* influxdb未授权访问漏洞
* Jackson-databind 反序列化漏洞 CVE-2017-7525+CVE-2017-17485
* Java RMI Registry 反序列化漏洞(=jdk8u111)
* JBoss 4.x JBossMQ JMS 反序列化漏洞 CVE-2017-7504
* JBoss JMXInvokerServlet 反序列化漏洞
* Jenkins远程命令执行漏洞 CVE-2018-1000861
* Jetty WEB-INF 敏感信息泄露漏洞 CVE-2021-28164
* Jetty WEB-INF 敏感信息泄露漏洞 CVE-2021-34429
* Jetty 通用 Servlets 组件 ConcatServlet 信息泄露漏洞 CVE-2021-28169
* Jmeter RMI 反序列化命令执行漏洞 CVE-2018-1297
* Joomla 3.7.0 SQL注入漏洞 CVE-2017-8917)
* Jupyter Notebook 未授权访问远程命令执行漏洞
* Kibana 原型链污染导致任意代码执行漏洞 CVE-2019-7609
* Kibana 本地文件包含漏洞 CVE-2018-17246
* Libssh 服务端权限认证绕过漏洞 CVE-2018-10933
* Liferay Portal CE 反序列化命令执行漏洞 CVE-2020-7961
* Magento 2.2 SQL注入漏洞
* Metabase任意文件读取漏洞 CVE-2021-41277
* mini_httpd任意文件读取漏洞 CVE-2018-18778
* Mojarra JSF ViewState 反序列化漏洞
* mongo-express 远程代码执行漏洞 CVE-2019-10758
* Mysql 身份认证绕过漏洞 CVE-2012-2122
* Nacos 认证绕过漏洞 CVE-2021-29441
* Neo4j Shell Server 反序列化漏洞 CVE-2021-34371
* Nexus Repository Manager 3 远程命令执行漏洞 CVE-2019-7238
* Nexus Repository Manager 3 远程命令执行漏洞 CVE-2020-10199
* Nexus Repository Manager 3 远程命令执行漏洞 CVE-2020-10204
* Nginx 文件名逻辑漏洞 CVE-2013-4547
* Nginx 解析漏洞
* Nginx 配置错误漏洞
* Nginx越界读取缓存漏洞 CVE-2017-7529
* node-postgres 代码执行漏洞 CVE-2017-16082
* Node.js 目录穿越漏洞 CVE-2017-14849
* ntopng权限绕过漏洞 CVE-2021-28073
* OpenSMTPD 远程命令执行漏洞 CVE-2020-7247
* OpenSSH 用户名枚举漏洞 CVE-2018-15473
* OpenSSL 心脏出血漏洞 CVE-2014-0160
* PHP-FPM Fastcgi 未授权访问漏洞
* PostgreSQL 高权限命令执行漏洞 CVE-2019-9193
* Python PIL 远程命令执行漏洞 CVE-2017-8291
* Python PIL 远程命令执行漏洞 CVE-2018-16509
* Python unpickle 造成任意命令执行漏洞
* Redis 4.x5.x 未授权访问漏洞
* Redis Lua沙盒绕过命令执行 CVE-2022-0543
* Rsync 未授权访问漏洞
* Ruby NetFTP 模块命令注入漏洞 CVE-2017-17405
* Ruby On Rails 路径穿越与任意文件读取漏洞 CVE-2019-5418
* Ruby On Rails 路径穿越漏洞 CVE-2018-3760
* SaltStack 任意文件读写漏洞 CVE-2020-11652
* SaltStack 命令注入漏洞 CVE-2020-16846
* SaltStack 水平权限绕过漏洞 CVE-2020-11651
* Samba 远程命令执行漏洞 CVE-2017-7494
* Scrapyd 未授权访问漏洞
* Shellshock 破壳漏洞 CVE-2014-6271
* Spring Cloud Function SpEL表达式命令注入 CVE-2022-22963
* Spring Cloud Gateway Actuator API SpEL表达式注入命令执行 CVE-2022-22947
* Spring Data Commons 远程命令执行漏洞 CVE-2018-1273
* Spring Data Rest 远程命令执行漏洞 CVE-2017-8046
* Spring Messaging 远程命令执行漏洞 CVE-2018-1270
* Spring Security OAuth2 远程命令执行漏洞 CVE-2016-4977
* Spring WebFlow 远程代码执行漏洞 CVE-2017-4971
* Spring框架Data Binding与JDK 9+导致的远程代码执行漏洞 CVE-2022-22965
* Struts2 S2-001 远程代码执行漏洞
* Struts2 S2-005 远程代码执行漏洞
* Struts2 S2-007 远程代码执行漏洞
* Struts2 S2-008 远程代码执行漏洞
* Struts2 S2-009 远程代码执行漏洞
* Struts2 S2-012 远程代码执行漏洞
* Struts2 S2-013 远程代码执行漏洞
* Struts2 S2-015 远程代码执行漏洞
* Struts2 S2-016 远程代码执行漏洞
* Struts2 S2-032 远程代码执行漏洞 CVE-2016-3081
* Struts2 S2-045 远程代码执行漏洞 CVE-2017-5638
* Struts2 S2-046 远程代码执行漏洞 CVE-2017-5638
* Struts2 S2-048 远程代码执行漏洞
* Struts2 S2-052 远程代码执行漏洞
* Struts2 S2-053 远程代码执行漏洞
* Struts2 S2-057 远程代码执行漏洞 CVE-2018-11776
* Struts2 S2-059 远程代码执行漏洞 CVE-2019-0230
* Struts2 S2-061 远程代码执行漏洞 CVE-2020-17530
* Supervisord 远程命令执行漏洞 CVE-2017-11610
* ThinkPHP 2.x 任意代码执行漏洞
* ThinkPHP5 5.0.225.1.29 远程代码执行漏洞
* ThinkPHP5 5.0.23 远程代码执行漏洞
* ThinkPHP5 SQL注入漏洞 && 敏感信息泄露
* Tiki Wiki CMS Groupware 认证绕过漏洞 CVE-2020-15906
* Tomcat PUT方法任意写文件漏洞 CVE-2017-12615
* Tomcat8 弱口令+后台getshell漏洞
* uWSGI PHP目录穿越漏洞 CVE-2018-7490
* uWSGI 未授权访问漏洞
* Weblogic  10.3.6 'wls-wsat' XMLDecoder 反序列化漏洞 CVE-2017-10271
* Weblogic SSRF漏洞
* Weblogic WLS Core Components 反序列化命令执行漏洞 CVE-2018-2628
* Weblogic 任意文件上传漏洞 CVE-2018-2894
* Weblogic 管理控制台未授权远程命令执行漏洞 CVE-2020-14882+CVE-2020-14883
* Webmin 远程命令执行漏洞 CVE-2019-15107
* Wordpress 4.6 任意命令执行漏洞 PwnScriptum
* XStream 反序列化命令执行漏洞 CVE-2021-21351
* XStream 反序列化命令执行漏洞 CVE-2021-29505
* XXL-JOB executor 未授权访问漏洞
* zabbix latest.php SQL注入漏洞 CVE-2016-10134
* Zabbix Server trapper命令注入漏洞 CVE-2017-2824
* Zabbix Server trapper命令注入漏洞 CVE-2020-11800
## 0x02 声明

本项目收集漏洞均源于互联网：

- Vulhub：https://github.com/vulhub/vulhub
