import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // TODO implement the status route
  // onionRouter.get("/status", (req, res) => {});
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });
  // /getLastReceivedEncryptedMessage
onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
  res.json({ result: null });
});

// /getLastReceivedDecryptedMessage
onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
  res.json({ result: null });
});

// /getLastMessageDestination
onionRouter.get("/getLastMessageDestination", (req, res) => {
  res.json({ result: null });
});
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
