import { ReactNativeAriesAskar } from 'aries-askar-react-native'
import { StyleSheet, Text, View } from 'react-native'

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
})

export default function App() {
  return (
    <View style={styles.container}>
      <Text>Askar version: {new ReactNativeAriesAskar().version()}</Text>
    </View>
  )
}
