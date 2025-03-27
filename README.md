README File
1.	Prerequisite:
Python 3.x
Required Libraries: cryptography, hashlib, socket
Steps to Run on Linux:
•	Open two Terminal windows 
•	python -m venv venv
•	source venv/bin/activate
•	pip install cryptography
•	Run “python3 Client.py” in one window
•	Run “python3 Server.py" in the other window

2.	Enter 1 for Login and 2 for Sign Up:
If Login Chosen: For logging to the server
 	Enter Username and Password
          If Sign Up Chosen: For signing up to the server
 	Enter Username, Password and Mobile Number
	Proceed to Login

3.	2FA:
Enter OTP sent to the mobile number
Login Successful!

4.	Choose option:
1.	List all uploads: It gives list of all uploaded files by the user.
2.	Upload a file: For uploading a file
Enter valid file name to upload
3.	Download a file
 		Enter valid file name to download
4.	Update a file
Enter valid file name to update
5.	Delete a file
       		Enter valid file name to delete a file
6.	Exit

