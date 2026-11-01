import type { NodeStatus } from "./types";

export const STATUS_COLOR: Record<NodeStatus, string> = {
  VERIFIED: "var(--color-verified)",
  LOCKED: "var(--color-verified)",
  ACTIVE: "var(--color-active)",
  DIRTY_OMISSION_RISK: "var(--color-dirty)",
  REJECTED: "var(--color-rejected)",
};

export const STATUS_LABEL: Record<NodeStatus, string> = {
  VERIFIED: "Verified",
  LOCKED: "Verified & locked",
  ACTIVE: "Active",
  DIRTY_OMISSION_RISK: "Dirty / omission risk",
  REJECTED: "Rejected",
};
