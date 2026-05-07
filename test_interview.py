import anthropic
from keys import ANTHROPIC_API_KEY

anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

messages = []
system_prompt = "You are interviewing a sysadmin about their environment to understand their vulnerability landscape."

print("Type 'quit' to exit.\n")

while True:
    user_input = input("You:").strip()
    if user_input.lower() == "quit":
        break

    messages.append({"role": "user", "content": user_input})

    response = anthropic_client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=system_prompt,
        messages=messages
    )

    assistant_reply = response.content[0].text
    messages.append({"role": "assistant", "content": assistant_reply})

    print(f"\nClaude: {assistant_reply}\n")