To export KnowBe4 data so custom reports can be created from it, you need a few things.


Reporting API KEY
To obtain a reporting API key, you need the appropriate permissions.
Reporting API Overview 


Fetching and reworking the data
The reporting API is described in detail.

KnowBe4 API Documentation 

I wrote two PowerShell scripts. The first retrieves data from KnowBe4 and saves it in a folder containing the user JSON files and the enrollments. The users file contains data about the users, such as their departments. The enrollments file is linked to the user ID and shows the status of their progress on specific training courses.

>> Fetch script

The API key is used in this script. To make this more secure, someone else may turn this into a .env setup, as long as they clearly describe exactly how it works!

The files are placed in a folder at the location where this script is run. This folder contains users and their training progress data. DO NOT LEAVE IT LYING AROUND! Delete this folder when you are done with it!

>> data transform
Put the data into an understandable Excel sheet.

Run this from the same directory as the fetch script.