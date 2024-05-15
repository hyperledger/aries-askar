import { Key, KeyAlgs, KeyBackend, ariesAskar } from '@hyperledger/aries-askar-react-native'
import { StyleSheet, Text, View } from 'react-native'

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
})

export const App = () => {
  const key = Key.generate(KeyAlgs.EcSecp256r1, KeyBackend.SecureElement)

  return (
    <View style={styles.container}>
      <Text>{ariesAskar.version()}</Text>
      <Text>Key: {key.publicBytes.join(',')}</Text>
    </View>
  )
}
