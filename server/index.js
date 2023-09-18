// server/index.js

const express = require("express");

const PORT = process.env.PORT || 3001;

const app = express();

const MongoClient = require('mongodb').MongoClient;

// Replace '<password>' with your actual password
const url = 'mongodb+srv://SuhaiBatman:Kawairun@123@smu2023.nzqvtse.mongodb.net/';

// Function to connect to MongoDB Atlas
async function connectToMongoDB() {
  try {
    const client = new MongoClient(url, { useNewUrlParser: true, useUnifiedTopology: true });

    // Connect to MongoDB
    await client.connect();

    console.log('Connected to MongoDB Atlas');

    // List databases
    const adminDb = client.db('admin');
    const adminDbResult = await adminDb.admin().listDatabases();

    console.log('Databases:');
    adminDbResult.databases.forEach((db) => {
      console.log(`- ${db.name}`);
    });

    // Close the connection
    client.close();
    console.log('Connection closed');
  } catch (err) {
    console.error('Error connecting to MongoDB Atlas:', err);
  }
}

// Call the function to connect
connectToMongoDB();


app.get("/api", (req, res) => {
    res.json({ message: "Hello from server!" });
  });
  
  app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`);
  });