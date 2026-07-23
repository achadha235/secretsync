import { Resource } from "sst";

export async function handler(event: any, context: any) {
  return {
    statusCode: 200,
    body: {
      secretOne: Resource.SecretOne.value,
      secretTwo: Resource.SecretTwo.value,
    },
  };
}
