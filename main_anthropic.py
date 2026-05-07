import anthropic
from keys import ANTHROPIC_API_KEY

anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

response = anthropic_client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system='You are a vulnerability prioritization expert.',
    messages=[
        {"role": "user", "content": "What's the most important factor in prioritizing a finding?"}
    ]
)

answer = response.content[0].text

print(f"\n{answer}\n")

