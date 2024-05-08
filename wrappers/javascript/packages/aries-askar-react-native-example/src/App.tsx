import { ariesAskar } from '@hyperledger/aries-askar-react-native'
import { StyleSheet, Text, View } from 'react-native'

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
})

export const App = () => (
  <View style={styles.container}>
    <Text>{ariesAskar.version()}</Text>
  </View>
)
