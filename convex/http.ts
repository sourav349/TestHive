import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { WebhookEvent } from "@clerk/nextjs/server";
import { Webhook } from "svix";
import { api } from "./_generated/api";

const http = httpRouter();

http.route({
  path: "/clerk-webhook",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    // Ensure the Clerk Webhook Secret is set
    const webhookSecret = process.env.CLERK_WEBHOOK_SECRET;
    if (!webhookSecret) {
      console.error("Missing CLERK_WEBHOOK_SECRET environment variable");
      return new Response("Configuration error", { status: 500 });
    }

    // Extract Svix headers from the request
    const svixId = request.headers.get("svix-id");
    const svixSignature = request.headers.get("svix-signature");
    const svixTimestamp = request.headers.get("svix-timestamp");

    if (!svixId || !svixSignature || !svixTimestamp) {
      console.error("Missing Svix headers");
      return new Response("Missing required headers", { status: 400 });
    }

    // Parse and verify the request payload
    let payload: any;
    try {
      payload = await request.json();
    } catch (err) {
      console.error("Failed to parse request payload:", err);
      return new Response("Invalid JSON payload", { status: 400 });
    }

    const body = JSON.stringify(payload);
    const webhook = new Webhook(webhookSecret);

    let evt: WebhookEvent;
    try {
      evt = webhook.verify(body, {
        "svix-id": svixId,
        "svix-timestamp": svixTimestamp,
        "svix-signature": svixSignature,
      }) as WebhookEvent;
    } catch (err) {
      console.error("Error verifying webhook:", err);
      return new Response("Invalid webhook signature", { status: 400 });
    }

    // Handle the event based on its type
    const eventType = evt.type;
    if (eventType === "user.created") {
      const { id, email_addresses, first_name, last_name, image_url } =
        evt.data;

      // Extract and validate user information
      const email = email_addresses?.[0]?.email_address;
      const name = `${first_name || ""} ${last_name || ""}`.trim();

      if (!id || !email) {
        console.error("Missing required user data in event");
        return new Response("Invalid event data", { status: 400 });
      }

      try {
        // Run the mutation to sync user data
        await ctx.runMutation(api.users.syncUser, {
          clerkId: id,
          email,
          name,
          image: image_url,
        });
      } catch (err) {
        console.error("Error creating user:", err);
        return new Response("Error syncing user data", { status: 500 });
      }
    } else {
      console.warn(`Unhandled event type: ${eventType}`);
    }

    return new Response("Webhook processed successfully", { status: 200 });
  }),
});

export default http;
