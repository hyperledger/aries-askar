import type { AriesAskar } from '../AriesAskar'

export let ariesAskar: AriesAskar

export const registerIndyVdr = ({ askar }: { askar: AriesAskar }) => (ariesAskar = askar)
