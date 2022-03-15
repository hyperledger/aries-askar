import type { TurboModule } from "react-native-tscodegen-types";
import { TurboModuleRegistry } from "react-native-tscodegen-types";

// General interface for the package. Our generated cpp wrapper will be based on this
export interface AriesAskarNativeBindings extends TurboModule {
  version(): string;
}

// We MUST export this according to tscodegen. We are ignoring it however.
export default TurboModuleRegistry.getEnforcing<AriesAskarNativeBindings>(
  "AriesAskar"
);
