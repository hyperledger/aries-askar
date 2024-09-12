import { KeyAlgs, KeyBackend, LocalKeyHandle, ariesAskar } from '@hyperledger/aries-askar-react-native'
import { authenticateAsync } from 'expo-local-authentication'
import { useState } from 'react'
import { Button, StyleSheet, Text, View } from 'react-native'

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
})

export const App = () => {
  const [signature, setSignature] = useState<Uint8Array>()

  const sign = async () => {
    const key = ariesAskar.keyGenerate({
      algorithm: KeyAlgs.EcSecp256r1,
      keyBackend: KeyBackend.SecureElement,
      ephemeral: false,
    })
    const result = await authenticateAsync()
    if (result.success) {
      const sig = ariesAskar.keySignMessage({
        message: new Uint8Array(10).fill(42),
        localKeyHandle: new LocalKeyHandle(key.handle),
      })
      setSignature(sig)
    } else {
      throw new Error('Could not authenticate')
    }
  }

  return (
    <View style={styles.container}>
      <Text>{ariesAskar.version()}</Text>
      <Button title="sign" onPress={sign} />
      {signature && <Text>{signature.join('.')}</Text>}
    </View>
  )
}
