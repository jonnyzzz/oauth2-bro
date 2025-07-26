# OAuth2-bro
OAuth2 server implementation with implicit authentication and authorization. 

Why?
----

The main use case for this authentication server is to establish **implicit** authentication of users,
to allow more seamless integration with corporate authentication and authorization systems. 

Eugene is focused on establishing management, security, and governance of AI and Developer Tools at a scale of companies.
His main focus is on [JetBrains IDE Services](https://jetbrains.com/ide-services), and this server is created to
support customers' requests. 

The naming comes from 1984's Big Brother story 

Use Cases
---------

In environments where authentication is not needed or not yet needed. Examples of such environments are
* University classrooms (where computers are still reused by students)
* Remote machines, which are getting popular in remote development scenarios or regulated businesses
* Implicit auth* scenarios
* Integration with corporate-deployed authorization/authentication systems
* Means to authorize machines, instead of humans

The OAuth2-bro server is compatible with the on-premises and the SaaS version of JetBrains IDE Services. 

Eugene believes there are many more use cases for that authentication server, which can be later added. 


License
-------

Apache 2.0, see LICENSE.txt in the repository


Distribution
------------

We use the Go language to implement the server. We believe it's easier to change/patch the program to
Implement the specific rules directly in the code (AI agents will help you!), compile, and deploy in Docker. 

We provide Docker builds and Docker images to simplify that work. 


Contribution
------------

Let's collect more scenarios and rules in this repository, and let's improve the missing parts of the
OAuth2-bro together. You are absolutely welcome to contribute. For big changes, please start with
an issue and a discussion. 
