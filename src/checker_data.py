import pydantic


class RefinementResult(pydantic.BaseModel):
    refined: bool
    checker_code: str
    result: str
    num_TP: int
    num_FP: int
    num_reports: int
    attempt_id: int

    def __str__(self):
        tp_rate = self.num_TP / (self.num_TP + self.num_FP + 0.00001)
        return f"{self.result},{tp_rate:.2f},{self.num_reports},{self.attempt_id}"
