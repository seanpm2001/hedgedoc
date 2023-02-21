/*
 * SPDX-FileCopyrightText: 2023 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import { AppExtension } from '../../../../extensions/base/app-extension'
import type { CheatsheetExtension } from '../../../editor-page/cheatsheet/cheatsheet-extension'
import type { MarkdownRendererExtension } from '../base/markdown-renderer-extension'
import { BasicMarkdownSyntaxMarkdownExtension } from './basic-markdown-syntax-markdown-extension'

export class BasicMarkdownSyntaxAppExtension extends AppExtension {
  buildMarkdownRendererExtensions(): MarkdownRendererExtension[] {
    return [new BasicMarkdownSyntaxMarkdownExtension()]
  }

  buildCheatsheetExtensions(): CheatsheetExtension[] {
    return [
      {
        i18nKey: 'basics.formatting',
        categoryI18nKey: 'basic',
        entries: [
          {
            i18nKey: 'basic'
          },
          {
            i18nKey: 'abbreviation'
          },
          { i18nKey: 'footnote' }
        ]
      },
      {
        i18nKey: 'basics.headlines',
        categoryI18nKey: 'basic',
        entries: [
          {
            i18nKey: 'hashtag'
          },
          {
            i18nKey: 'equal'
          }
        ]
      },
      {
        i18nKey: 'basics.code',
        categoryI18nKey: 'basic',
        entries: [{ i18nKey: 'inline' }, { i18nKey: 'block' }]
      },
      {
        i18nKey: 'basics.lists',
        categoryI18nKey: 'basic',
        entries: [{ i18nKey: 'unordered' }, { i18nKey: 'ordered' }]
      },
      {
        i18nKey: 'basics.images',
        categoryI18nKey: 'basic',
        entries: [{ i18nKey: 'basic' }, { i18nKey: 'size' }]
      },
      {
        i18nKey: 'basics.links',
        categoryI18nKey: 'basic'
      }
    ]
  }
}