from ragas.metrics import AgentGoalAccuracyWithoutReference, ToolCallAccuracy
from ragas.dataset_schema import MultiTurnSample, EvaluationDataset
from ragas.messages import HumanMessage, AIMessage, ToolMessage, ToolCall
from ragas import evaluate
def _clean_llm_output(text: str) -> str:
    """Supprime les backticks markdown que Qwen ajoute parfois."""
    text = text.strip()
    if text.startswith("```"):
        # Supprimer ```json ... ``` ou ``` ... ```
        lines = text.split("\n")
        # Enlever première ligne (```json) et dernière (```)
        inner = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(inner).strip()
    return text
def evaluate_agent_run(state: dict, llm) -> dict:
    turns = []
    reference_tool_calls = []

    for log in state.get("agent_logs", []):
        if log.get("input"):
            turns.append(HumanMessage(content=log["input"]))

        if log.get("tool_name") and log.get("tool_args"):
            tool_call = ToolCall(
                name=log["tool_name"],
                args=log["tool_args"],
            )
            reference_tool_calls.append(tool_call)
            turns.append(AIMessage(
                content=f"Calling tool: {log['tool_name']}",
                tool_calls=[tool_call],
            ))

        if log.get("tool_output"):
            turns.append(ToolMessage(content=str(log["tool_output"])))

        if log.get("output"):
            # CORRECTION — nettoyer la sortie LLM avant de la passer à RAGAS
            clean_output = _clean_llm_output(str(log["output"]))
            turns.append(AIMessage(content=clean_output))

    if not turns:
        print("[RAGAS AGENT] No agent_logs found in state")
        return {}

    if not isinstance(turns[0], HumanMessage):
        turns.insert(0, HumanMessage(content="Analyze the following CTI message"))

    sample = MultiTurnSample(
        user_input=turns,
        reference=str(
            state.get("aggregated_report", {}).get("global_severity", "unknown")
        ),
        reference_tool_calls=reference_tool_calls if reference_tool_calls else None,
    )

    dataset = EvaluationDataset(samples=[sample])
    metrics = [AgentGoalAccuracyWithoutReference(llm=llm)]
    if reference_tool_calls:
        metrics.append(ToolCallAccuracy())

    try:
        results = evaluate(
        dataset=ragas_dataset,
        metrics=[faithfulness, answer_relevancy, context_precision, context_recall],
        llm=evaluator_llm,
        run_config=RunConfig(max_workers=1)  # évite le rate limit Gemini
    )
    except Exception as e:
        print(f"[RAGAS AGENT] ❌ Evaluation failed: {e}")
        return {}

    scores = {}
    if result.scores and "agent_goal_accuracy_without_reference" in result.scores[0]:
        scores["agent_goal_accuracy"] = round(
            result.scores[0]["agent_goal_accuracy_without_reference"], 3
        )
    if result.scores and "tool_call_accuracy" in result.scores[0]:
        scores["tool_call_accuracy"] = round(
            result.scores[0]["tool_call_accuracy"], 3
        )

    print(f"\n[RAGAS AGENT] Results")
    for k, v in scores.items():
        print(f"  {k}: {v}")

    return scores
