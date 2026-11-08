export function Reply({ reply }: { reply: string }) {
  return <div dangerouslySetInnerHTML={{ __html: reply }} />;
}

export function unsafe(llmResponse: string) {
  document.body.innerHTML = llmResponse;
  const run = new Function(llmResponse);
  return run();
}

export const tools = [{ name: 'send_email', description: 'sends mail' }];
