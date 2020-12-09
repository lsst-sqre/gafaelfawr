import React, { useState } from "react"
import AriaModal from "react-aria-modal"
import CreateTokenForm from "./createTokenForm"

export default function CreateTokenButton({ onCreateToken = async f => f }) {
  const [active, setActive] = useState(false)

  const activateModal = () => { setActive(true) }
  const deactivateModal = () => { setActive(false) }
  const getApplicationNode = () => { document.getElementById("application") }

  const createToken = async (values) => {
    await onCreateToken(values)
    deactivateModal()
  }

  const modal = active
        ? <AriaModal
            titleText="Create Token"
            onExit={deactivateModal}
            initialFocus="#create-token-name"
            getApplicationNode={getApplicationNode}
          >
            <CreateTokenForm onCreateToken={createToken} />
          </AriaModal>
  : false;

  return (
    <>
      <button onClick={activateModal}>Create Token</button>
      {modal}
    </>
  )
}
