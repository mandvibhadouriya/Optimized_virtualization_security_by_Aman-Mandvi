# Optimized Virtualized Storage Security: Ensuring Data Integrity and Confidentiality in a Virtualization Environment

## About our Project

Enhancing the security of virtualized storage systems to guarantee the integrity and confidentiality of data within a virtualized environment is the technical goal of the project "Optimized Virtualized Storage Security: Ensuring Data Integrity and Confidentiality in a Virtualization Environment." This project is essential in addressing the security challenges that arise when using virtualization technologies, as these technologies introduce unique vulnerabilities and risks.

The technical aspects of this project can be broken down into several key components:

1. **Virtualized Storage Security:** 
   The project starts by addressing the security challenges specific to virtualized storage. Virtualization involves the abstraction of physical storage resources, which can make data more susceptible to unauthorized access and tampering.
   
2. **Encryption and Decryption:** 
   To ensure data confidentiality, the project incorporates encryption techniques. This involves encrypting data at rest and in transit. The project utilizes the Fernet symmetric encryption algorithm for this purpose. The encryption key used in the project, stored as `key`, is employed for both encryption and decryption processes.
   
3. **Data at Rest Security:** 
   Data at rest refers to data stored on physical disks. The project provides a mechanism for encrypting data when it is stored using the Fernet encryption key. Users can encrypt and decrypt data using the provided GUI interface.
   
4. **Data in Transit Security:** 
   Data in transit refers to data being transferred over a network. The project provides the capability to send encrypted data over a network connection, ensuring that data remains confidential during transmission. Data is encrypted using the Fernet algorithm before being sent and decrypted upon reception.
   
5. **Data Integrity:** 
   To ensure data integrity, the project calculates and verifies the hash values of data using the Blake2b hash function. The hash values are used to detect any tampering or corruption of the data.
   
6. **User-Friendly GUI:** 
   The project incorporates a Graphical User Interface (GUI) to make it user-friendly. Users have the ability to choose whether they want to work with data at rest or data in transit, select data or files for encryption or decryption, and view the results.
   
7. **Performance and Optimization:** 
   While ensuring security, the project aims for optimal performance. It measures the time taken for data transmission, which is important for assessing the efficiency of the encryption and transmission processes.
   
8. **Error Handling:** 
   The project provides error handling mechanisms to deal with issues such as incorrect keys or file paths. It provides feedback to users in cases of decryption failures and other issues.
   
9. **Data Storage:** 
   The project saves both encrypted and decrypted data to files for reference. This is crucial for preserving data for future analysis, auditing, or other purposes.
   
10. **Networking and Socket Programming:** 
    The project utilizes socket programming to establish network connections between sender and receiver components. This enables the secure transmission of data in a virtualized environment.
    
11. **Security Key Management:** 
    The project assumes that users possess the encryption key, which must be kept confidential. Key management is critical in any encryption-based project, and secure key storage and distribution mechanisms are essential.
    
12. **Result Presentation:** 
    The project offers a result presentation mechanism that opens a new window displaying the original data, encrypted data, hash value, and transmission time. This feature enhances the user experience and facilitates result analysis.
    
13. **User Experience and Interaction:** 
    The GUI components of the project are designed to make it accessible to users who may not have in-depth technical knowledge. Users can choose options, browse files, and visualize results in a user-friendly manner.

## Data Encryption Project

This project demonstrates data encryption techniques for data at rest and in transit.

### Features

* Encrypt and decrypt data using the `cryptography` library.
* Choose between "Data at Rest" and "Data in Transit" options.
* User-friendly GUI for both sender and receiver.

### Prerequisites

* Python (https://www.python.org/)
* `cryptography` library (`pip install cryptography`)
* Network connectivity between sender and receiver

### Installation

**Both Sender and Receiver:**

1. **Install Python:** Download and install Python from the official website.
2. **Install `cryptography` library:** Open a terminal/command prompt and run `pip install cryptography`.

**Sender:**

1. **Download/Clone Code:** Download or clone the sender code onto the machine.
2. **Navigate to Directory:** Open a terminal/command prompt and navigate to the sender code directory.
3. **Run Sender:** Execute the sender code using `python sender.py`.
4. **Choose Option:** Select "Data at Rest" or "Data in Transit" from the GUI and follow instructions.

**Receiver:**

1. **Download/Clone Code:** Download or clone the receiver code onto the machine.
2. **Navigate to Directory:** Open a terminal/command prompt and navigate to the receiver code directory.
3. **Run Receiver:** Execute the receiver code using `python receiver.py`.
4. **Receive Data:** Click the "Receive Data" button on the GUI to initiate data reception.

**Note:**

* The sender and receiver components must run on separate machines.
* Replace `192.168.79.1` in the receiver code with the actual sender's IP address.
* Ensure network connectivity between sender and receiver.
* Share the provided encryption key (`key`) securely between both parties.

### Contributing

We welcome contributions to this project! Please see the CONTRIBUTING.md file for guidelines.
