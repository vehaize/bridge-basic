export const CLAIM_ORIGIN_SENTENCE: string;

export interface DeadlineConstants {
  min: string;
  max: string;
  deadlineDefault: string;
}

export function readDeadlineConstants(source: string): DeadlineConstants;
export function deadlineSentence(constants: DeadlineConstants): string;
export function checkDeadlineText(file: string, text: string, constants: DeadlineConstants): string[];
export function checkRepository(root: string): string[];
