A stress test is implemented to observe how LANGuard’s system behavior under different levels of stress. Locust is the tool used for this test since backend routes are written in Python, and connect to the Flask app. Three frequent used routes are put on test, /login, /dashboard, and /alert to evaluate how the system handles stress. Three tests are executed for comparison purposes, in which test concurrent users, request per second, failures, and response time for each of these routes. To prevent using an aggressive load to the system at once, load is started low with 20 concurrent users and increased until reaching 100 for the last test, 10 seconds to reach full load applied to all these three tests. 

Result:

<img width="507" height="152" alt="Screen Shot 2026-04-19 at 23 39 02" src="https://github.com/user-attachments/assets/9628b8c4-c66d-43a5-8f3a-bf47f7000daf" />

From the result, the average response for these routes in the three tests stays low at around 10ms. The response time for 95% of the requests also remains stable, within 24ms. Besides, request per second noticeably changes from ~10 to ~50 at peak load showing the increasing throughput. Furthermore, no request failure or bottleneck is observed as shown in the data. 


Test 1: Number of users: 20, Spawn rate: 2
<img width="799" height="712" alt="Screen Shot 2026-04-17 at 23 27 16" src="https://github.com/user-attachments/assets/2e9c7239-2a06-4653-b251-6e2a05a52a36" />
<img width="585" height="684" alt="Screen Shot 2026-04-17 at 23 27 57" src="https://github.com/user-attachments/assets/c329dfcb-03ed-4c32-be1c-ce08acbda96f" />

Test 2: Number of users: 50, Spawn rate: 5
<img width="796" height="703" alt="Screen Shot 2026-04-17 at 23 29 13" src="https://github.com/user-attachments/assets/27dbdb0b-4e90-4b8f-85a5-c4552f650502" />
<img width="586" height="690" alt="Screen Shot 2026-04-17 at 23 29 53" src="https://github.com/user-attachments/assets/b46f1665-2bdc-4f5b-9ad1-3739c4bf0bfc" />

Test 3: Number of users: 100, Spawn rate: 10
<img width="801" height="703" alt="Screen Shot 2026-04-17 at 23 34 40" src="https://github.com/user-attachments/assets/da90976d-ebb2-4f53-a6bf-6a12a0a0e750" />
<img width="586" height="682" alt="Screen Shot 2026-04-17 at 23 35 07" src="https://github.com/user-attachments/assets/318dc6bd-b323-4fe1-8f38-3976d2a0ff81" />
