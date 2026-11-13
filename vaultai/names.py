"""Common Indian first names and surnames.

General-purpose NER models are trained mostly on Western news text and miss many
Indian names ("Call Priya Sharma"). A small lookup list is a cheap, explainable way
to recover them. A match needs a capitalised word from the first-name list,
optionally followed by capitalised surname words, so "priya" in lower case or the
word "Raj" inside "Rajasthan" do not trigger it.
"""
import re

FIRST_NAMES = """
Aarav Aditya Akash Amit Anand Anil Ankit Ankur Arjun Arun Ashish Ashok Ayush Deepak Dev Dhruv
Gaurav Harsh Hemant Ishaan Jatin Karan Kartik Kunal Lokesh Manish Manoj Mayank Mohit Mukesh
Naveen Nikhil Nitin Pankaj Pradeep Pranav Prateek Rahul Raj Rajat Rajesh Rakesh Ramesh Ravi
Rohan Rohit Sachin Sahil Sameer Sandeep Sanjay Saurabh Shivam Shubham Siddharth Sumit Sunil
Suresh Tarun Tushar Varun Vikas Vikram Vinay Vineet Vishal Vivek Yash Yogesh Abhishek Ajay
Akhil Alok Aman Amar Arvind Bharat Chetan Dinesh Gopal Hari Imran Irfan Jay Kamal Kishore
Krishna Mahesh Mohan Naresh Om Prakash Prem Raghav Ram Sanjeev Satish Shankar Shyam Sunny
Uday Umesh Vijay Vinod Mohammed Mohammad Faiz Arif Salman Aamir Zaid Farhan Ayaan Kabir Reyansh
Aanya Aditi Ananya Anjali Ankita Anushka Aparna Archana Arti Bhavna Deepika Divya Diya Gauri
Isha Ishita Jyoti Kajal Kavita Kavya Khushi Kiran Komal Lakshmi Manisha Meena Megha Neha Nidhi
Nikita Nisha Pooja Prachi Pallavi Preeti Priya Priyanka Radha Rani Rashmi Rekha Ritu Riya Sakshi
Sangeeta Sanjana Sapna Sarita Shalini Shikha Shreya Shruti Simran Sneha Sonal Sonam Sunita
Swati Tanvi Tanya Usha Vandana Varsha Vidya Yamini Zoya Fatima Ayesha Sana Anushree Mansi
Harleen Gurpreet Manpreet Jaspreet Harpreet Navjot Simranjeet Lakshman Venkat Srinivas Karthik
Lakshmi Meenakshi Padma Revathi Suresh Arjun Balaji Ganesh Murali Senthil Vignesh Anitha Deepa
""".split()

SURNAMES = """
Sharma Verma Gupta Singh Kumar Agarwal Aggarwal Jain Mehta Shah Patel Desai Joshi Kulkarni
Deshpande Patil Pawar Jadhav Shinde More Iyer Iyengar Nair Menon Pillai Reddy Rao Naidu
Choudhary Chaudhary Yadav Mishra Pandey Tiwari Dubey Shukla Srivastava Saxena Chauhan Rathore
Thakur Bhatt Bhat Kapoor Khanna Malhotra Chopra Arora Bansal Goel Goyal Mittal Jindal Garg
Sethi Ahuja Bajaj Banerjee Chatterjee Mukherjee Ghosh Bose Das Dutta Sen Roy Chakraborty
Sinha Jha Prasad Mahato Nayak Mohanty Behera Panda Hegde Shetty Kamath Pai Gowda Krishnan
Subramanian Venkatesh Raman Sundaram Natarajan Khan Ansari Qureshi Siddiqui Sheikh Syed Ali
Hussain Rizvi Gill Sandhu Dhillon Sidhu Grewal Bedi Sodhi Kaur Dsouza Fernandes Pereira
Rodrigues Thomas Mathew Varghese Kurian Bhattacharya Tripathi Dwivedi Trivedi Vyas Parikh
Modi Gandhi Soni Rawat Negi Bisht Rana Tomar Bhardwaj Kashyap Vohra Tandon Kohli Talwar
""".split()

_FIRST = "|".join(sorted(set(FIRST_NAMES), key=len, reverse=True))
_SUR = "|".join(sorted(set(SURNAMES), key=len, reverse=True))

# First name, optionally followed by up to two capitalised words (surname / middle name),
# OR a capitalised word followed by a known surname ("Mr X Sharma" style without title).
NAME_LIST_RE = re.compile(
    rf"\b(?:(?:{_FIRST})(?:\s+[A-Z][a-z]+){{0,2}}|[A-Z][a-z]+\s+(?:{_SUR}))\b"
)
