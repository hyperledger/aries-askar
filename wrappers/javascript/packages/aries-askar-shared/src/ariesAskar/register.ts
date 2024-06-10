import type { AriesAskar } from './AriesAskar'

export let ariesAskar: AriesAskar

export const registerAriesAskar = ({ askar }: { askar: AriesAskar }) => (ariesAskar = askar)
