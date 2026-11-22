import OpenAI from "openai";

// [LỖ HỔNG 1 - Hardcoded Secret chia mảnh]: Né Regex quét chuỗi 'sk-ant-' liền mạch
const keyChunks = ["sk", "ant", "api03", "9x8y7z6w5v4u3t2s1r0q9p8o7n6m5l4k"];
const client = new OpenAI({ apiKey: keyChunks.join("-") });

// [LỖ HỔNG 2 - Prompt Injection qua Tagged Template]
function buildPrompt(strings: TemplateStringsArray, ...values: string[]): string {
  return strings.reduce((acc, str, i) => acc + str + (values[i] ?? ""), "");
}

export async function processUserRequest(userInput: string): Promise<unknown> {
  const prompt = buildPrompt`Analyze this request and return a JS expression: ${userInput}`;

  const completion = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: prompt }],
  });

  const aiOutput = completion.choices[0]?.message?.content ?? "null";

  // [LỖ HỔNG 3 - Insecure Output Handling / RCE]: Dùng Function constructor thay cho eval()
  const evaluator = new Function("return (" + aiOutput + ")");
  return evaluator();
}