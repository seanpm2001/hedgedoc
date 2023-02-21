/*
 * SPDX-FileCopyrightText: 2023 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import { optionalAppExtensions } from '../../../../extensions/extra-integrations/optional-app-extensions'
import { ShowIf } from '../../../common/show-if/show-if'
import type { CheatsheetEntry, CheatsheetExtension } from '../../cheatsheet/cheatsheet-extension'
import { isCheatsheetGroup } from '../../cheatsheet/cheatsheet-extension'
import { CategoryAccordion } from './category-accordion'
import { CheatsheetEntryPane } from './cheatsheet-entry-pane'
import { TopicSelection } from './topic-selection'
import React, { useCallback, useMemo, useState } from 'react'
import { Col, ListGroup, Modal, Row } from 'react-bootstrap'

/**
 * Renders the tab content for the cheatsheet.
 */
export const CheatsheetModalBody: React.FC = () => {
  const [selectedExtension, setSelectedExtension] = useState<CheatsheetExtension>()
  const [selectedEntry, setSelectedEntry] = useState<CheatsheetEntry>()

  const changeExtension = useCallback((value: CheatsheetExtension) => {
    setSelectedExtension(value)
    setSelectedEntry(isCheatsheetGroup(value) ? value.entries[0] : value)
  }, [])

  const extensions = useMemo(
    () => optionalAppExtensions.flatMap((extension) => extension.buildCheatsheetExtensions()),
    []
  )

  return (
    <Modal.Body>
      <Row className={`mt-2`}>
        <Col xs={3}>
          <CategoryAccordion
            extensions={extensions}
            selectedEntry={selectedExtension}
            onStateChange={changeExtension}
          />
        </Col>
        <Col xs={9}>
          <ListGroup>
            <TopicSelection
              extension={selectedExtension}
              selectedEntry={selectedEntry}
              setSelectedEntry={setSelectedEntry}></TopicSelection>
            <ShowIf condition={selectedEntry !== undefined}>
              <CheatsheetEntryPane
                rootI18nKey={isCheatsheetGroup(selectedExtension) ? selectedExtension.i18nKey : undefined}
                extension={selectedEntry as CheatsheetEntry}
              />
            </ShowIf>
          </ListGroup>
        </Col>
      </Row>
    </Modal.Body>
  )
}