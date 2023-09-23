import pymongo

connection_string = "mongodb+srv://SuhaiBatmman:CSE-3311-password-5458@cse-3311-cluster.m7tu4qj.mongodb.net/"

try:
    client = pymongo.MongoClient(connection_string)

    db = client.get_database('cse-3311-cluster')

    print("Connected to MongoDB Atlas")

    collection = db['listingsAndReviews']
    documents = collection.find_one({"name": "Dhrutik Solanki"})

    print(documents)
    print(documents)

    client.close()
    print("Disconnected from MongoDB Atlas")

except pymongo.errors.ConnectionFailure as e:
    print("Error connecting to MongoDB Atlas:", e)
