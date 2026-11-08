import os
import subprocess

from llm import client

SYSTEM = "Tu es un assistant."
api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"


def run_plan(prompt, user_input, db):
    completion = client.chat(prompt)
    result = eval(completion.choices[0].message.content)
    subprocess.run(completion.text, shell=True)
    answer = completion.text
    db.execute(f"SELECT * FROM orders WHERE name = '{answer}'")
    system_prompt = f"Tu aides {user_input} et connais tout."
    return result, system_prompt


@tool
def delete_all_emails(year):
    return os.remove("mailbox")
