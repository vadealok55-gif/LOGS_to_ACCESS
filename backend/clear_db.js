const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

async function deleteCollection(collectionPath, batchSize) {
  const collectionRef = db.collection(collectionPath);
  const query = collectionRef.orderBy('__name__').limit(batchSize);

  return new Promise((resolve, reject) => {
    deleteQueryBatch(query, resolve).catch(reject);
  });
}

async function deleteQueryBatch(query, resolve) {
  const snapshot = await query.get();

  const batchSize = snapshot.size;
  if (batchSize === 0) {
    // When there are no documents left, we are done
    resolve();
    return;
  }

  // Delete documents in a batch
  const batch = db.batch();
  snapshot.docs.forEach((doc) => {
    batch.delete(doc.ref);
  });
  await batch.commit();

  // Recurse on the next process tick, to avoid
  // exploding the stack.
  process.nextTick(() => {
    deleteQueryBatch(query, resolve);
  });
}

async function run() {
    console.log("Cleaning up Firestore test data...");
    
    console.log("Deleting join_requests...");
    await deleteCollection('join_requests', 50);
    
    console.log("Deleting resources...");
    await deleteCollection('resources', 50);
    
    console.log("Deleting org_members...");
    await deleteCollection('org_members', 50);
    
    console.log("Deleting organizations...");
    await deleteCollection('organizations', 50);
    
    console.log("Done! All test organizations and related records have been deleted.");
    process.exit(0);
}

run().catch(console.error);
