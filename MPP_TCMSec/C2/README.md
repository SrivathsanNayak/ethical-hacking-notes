# Intro to C2

* C2 (Command and Control) - techniques & tools used to persist & communicate in target environment; tools such as Covenant and Metasploit can be used.

* Covenant dashboard includes components like Grunts, Listeners and Taskings.

* Grunts are user sessions that we have with target machine; Taskings keep track of all the commands run, with outputs.

* Covenant offers a lot of other inbuilt tools & options that can be used to interact with target machine, making C2 easier.

* In Windows, session isolation is practised; only system processes & services are executed in Session 0; user logs on to other sessions.

* In Covenant, we have session integrity as well - there are low, medium, high and System session integrities, according to the privileges of the session.
