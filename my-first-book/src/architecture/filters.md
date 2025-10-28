# Filters

![alt text](image.png)

- Filter receives the Servlet request, Servlet response, and FilterChain
- It can do anything, ranging from:
    - Logging
    - Modifying the original request
    - Sending a servlet response
- It will either end the chain (in the case of writing a response) or relay to the next filters in the chain