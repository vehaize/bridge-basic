export function stripFunding(lock: unknown): number;

export function stripLockfile(path: string): { removed: number; changed: boolean };

export function findFundingUrls(text: string): { index: number }[];

export function checkText(file: string, text: string): string[];

export function checkRepository(root: string): string[];

export function trackedPaths(root: string): string[];
