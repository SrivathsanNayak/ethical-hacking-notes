# OnlyHacks - Easy

* checking the instance, we have a webpage at '/login' for the OnlyHacks website

* besides the login form at '/login', we also have an option to sign up at '/register'

* after creating a test account, we are able to login and access the '/dashboard' page

* we can accept all the 'matches' and navigate to the matched users at '/chat'

* here, we have a person Renata in the chat option - clicking on this leads to '/chat/?rid=6', where we have an option for text input to chat

* the 'rid' parameter seems to be the user ID parameter - we can test for IDOR by changing the 'rid' parameter value to different numbers

* if we change the value to a number like 0 or 1, we get 500 Internal Server Error

* however, checking for 'rid=3', we get a different chat - and this contains the flag required
