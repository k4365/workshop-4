import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

// Array to store registered nodes
const registeredNodes: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // Route to check the status of the registry
  _registry.get("/status", (req: Request, res: Response) => {
    res.send("Registry is live");
  });

  // Route to register a new node
  _registry.post("/registerNode", (req: Request<{}, {}, RegisterNodeBody>, res: Response) => {
    const { nodeId, pubKey } = req.body;
    // Check if the node is already registered
    const existingNode = registeredNodes.find(node => node.nodeId === nodeId);
    if (existingNode) {
      res.status(400).send(`Node ${nodeId} is already registered`);
    } else {
      registeredNodes.push({ nodeId, pubKey });
      console.log(`Node ${nodeId} registered successfully`);
      res.send(`Node ${nodeId} registered successfully`);
    }
  });

  // Route to retrieve the node registry
  _registry.get("/getNodeRegistry", (req: Request, res: Response<GetNodeRegistryBody>) => {
    const responseBody: GetNodeRegistryBody = { nodes: registeredNodes };
    res.json(responseBody);
  });

  // Start the registry server
  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
